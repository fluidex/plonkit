#![allow(dead_code)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::let_and_return)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::single_char_pattern)]

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

pub mod pb {
    tonic::include_proto!("plonkitserver");
}

#[derive(Clone, PartialEq)]
pub enum CoreResult {
    Prove(pb::ProveResponse),
    Validate(pb::ValidateResponse),
}

impl CoreResult {
    pub fn into_prove(self) -> pb::ProveResponse {
        match self {
            Self::Validate(ret) => pb::ProveResponse {
                is_valid: ret.is_valid,
                error_msg: ret.error_msg,
                time_cost: 0.0,
                proof: Vec::new(),
                inputs: Vec::new(),
            },
            Self::Prove(ret) => ret,
        }
    }

    pub fn success(validate_only: bool) -> Self {
        match validate_only {
            true => Self::Validate(pb::ValidateResponse {
                is_valid: true,
                error_msg: String::new(),
            }),
            false => Self::Prove(pb::ProveResponse {
                is_valid: true,
                error_msg: String::new(),
                time_cost: 0.0,
                proof: Vec::new(),
                inputs: Vec::new(),
            }),
        }
    }

    pub fn any_prove_error<T, E>(err_ret: Result<T, E>, validate_only: bool) -> Self
    where
        T: std::fmt::Debug,
        E: std::fmt::Display,
    {
        match validate_only {
            true => Self::Validate(pb::ValidateResponse {
                is_valid: false,
                error_msg: format!("{}", err_ret.unwrap_err()),
            }),
            false => Self::Prove(pb::ProveResponse {
                is_valid: false,
                error_msg: format!("{}", err_ret.unwrap_err()),
                time_cost: 0.0,
                proof: Vec::new(),
                inputs: Vec::new(),
            }),
        }
    }
}

type ProveResultNotify = oneshot::Sender<CoreResult>;
type ProveRequest = (pb::ProveRequest, bool, ProveResultNotify);
pub type ProveCore = Box<dyn Fn(Vec<u8>, bool) -> CoreResult + Send>;

pub struct ServerOptions {
    pub server_addr: Option<String>,
    pub build_prove_core: Box<dyn FnOnce() -> ProveCore + Send>,
}

struct GrpcHandler {
    prove_tasks: Arc<Mutex<VecDeque<ProveRequest>>>,
    cur_task: Arc<Mutex<Option<String>>>,
    prove_send: mpsc::Sender<ProveRequest>,
}

impl ServerOptions {
    fn build_server(&self, prove_send: mpsc::Sender<ProveRequest>) -> GrpcHandler {
        GrpcHandler {
            prove_tasks: Arc::new(Mutex::new(VecDeque::with_capacity(32))),
            cur_task: Arc::new(Mutex::new(None)),
            prove_send,
        }
    }
}

async fn schedule_prove_task(
    mut notify: mpsc::Receiver<ProveRequest>,
    tasks: Arc<Mutex<VecDeque<ProveRequest>>>,
    cur_task_name: Arc<Mutex<Option<String>>>,
    core_build: Box<dyn FnOnce() -> ProveCore + Send>,
) {
    let mut prove_task_h = tokio::task::spawn_blocking(move || {
        log::info!("Building proving core ...");
        let core = core_build();
        log::info!("Building proving core done");
        core
    });

    loop {
        let is_task_active = cur_task_name.lock().await.is_some() || !tasks.lock().await.is_empty();

        tokio::select! {
            h_ret = &mut prove_task_h, if is_task_active => {

                //if joinerror, we are over
                let core = h_ret.unwrap();

                let last = match tasks.lock().await.pop_back() {
                    Some((req, valid_only, notify)) => {
                        let last_cur = cur_task_name.lock().await.replace(req.task_name.clone());
                        log::debug!("Trigger handling new task {}", req.task_name);

                        //DO prove/valid task
                        prove_task_h = tokio::task::spawn_blocking(move||{
                            if notify.send(core(req.witness, valid_only)).is_err(){
                                log::warn!("Send task {} result failure", req.task_name);
                            }
                            core
                        });

                        last_cur
                    },
                    _ => {
                        //put the core into joinhandle ("The Sword in the Stone")
                        prove_task_h = tokio::task::spawn_blocking(move||{core});
                        cur_task_name.lock().await.take()
                    }
                };

                if let Some(task_name) = last {
                    log::info!("Task {} is proven", task_name);
                }
            }
            Some(newtask) = notify.recv() => {
                log::debug!("Receive new task {}", newtask.0.task_name);
                tasks.lock().await.push_front(newtask);
            }
            else => {
                //everything is over (receiver is closed and no active task), we just leave
                return;
            }
        }
    }
}

use pb::plonkit_server_server::{PlonkitServer, PlonkitServerServer};

#[tonic::async_trait]
impl PlonkitServer for GrpcHandler {
    async fn prove(&self, request: tonic::Request<pb::ProveRequest>) -> Result<tonic::Response<pb::ProveResponse>, tonic::Status> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.prove_send.send((request.into_inner(), false, tx)).await {
            return Err(tonic::Status::internal(format!("send prove request fail: {}", e)));
        }

        match rx.await {
            Ok(CoreResult::Prove(ret)) => Ok(tonic::Response::new(ret)),
            Ok(_) => Err(tonic::Status::internal("prove core return unmatched ret type")),
            Err(e) => Err(tonic::Status::internal(format!("recv prove response fail: {}", e))),
        }
    }
    async fn validate_witness(
        &self,
        request: tonic::Request<pb::ProveRequest>,
    ) -> Result<tonic::Response<pb::ValidateResponse>, tonic::Status> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.prove_send.send((request.into_inner(), true, tx)).await {
            return Err(tonic::Status::internal(format!("send prove request fail: {}", e)));
        }

        match rx.await {
            Ok(CoreResult::Validate(ret)) => Ok(tonic::Response::new(ret)),
            Ok(_) => Err(tonic::Status::internal("prove core return unmatched ret type")),
            Err(e) => Err(tonic::Status::internal(format!("recv prove response fail: {}", e))),
        }
    }
    async fn status(&self, _request: tonic::Request<pb::EmptyRequest>) -> Result<tonic::Response<pb::StatusResponse>, tonic::Status> {
        let cur = self.cur_task.lock().await;
        Ok(tonic::Response::new(pb::StatusResponse {
            avaliable: cur.is_none(),
            current_task_name: cur.as_ref().map(String::clone).unwrap_or_else(String::new),
        }))
    }
}

use futures::future::TryFutureExt;

pub fn run(opt: ServerOptions) {
    env_logger::init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime")
        .block_on(async move {
            //just set a magic number because we always keep pumping request
            let (tx, rx) = mpsc::channel(16);
            let svr = opt.build_server(tx);
            let addr = opt.server_addr.unwrap_or_else(|| String::from("0.0.0.0:50055"));
            let buildcore = opt.build_prove_core;
            log::info!("Starting grpc server at {}", addr);

            let tasks_scheduled = svr.prove_tasks.clone();
            let status_scheduled = svr.cur_task.clone();
            let scheduler = tokio::spawn(async move {
                schedule_prove_task(rx, tasks_scheduled, status_scheduled, buildcore).await;
            });

            tonic::transport::Server::builder()
                .add_service(PlonkitServerServer::new(svr))
                .serve_with_shutdown(
                    addr.parse().unwrap(),
                    tokio::signal::ctrl_c().unwrap_or_else(|_| panic!("failed to listen for event")),
                )
                .await
                .unwrap();
            log::info!("Server shutted down");
            scheduler.await.unwrap();
        });

    log::info!("Running finish");
}
