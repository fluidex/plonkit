#![allow(dead_code)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::let_and_return)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::single_char_pattern)]

use crate::pb;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

#[derive(Clone, Debug, PartialEq)]
pub struct ErrDetail {
    is_valid: bool,
    error_msg: String,
}

#[derive(Clone, PartialEq)]
pub enum ServerResult {
    ForValidate(pb::ValidateResponse),
    ForProve(pb::ProveResponse),
    Error(ErrDetail),
}

impl From<ServerResult> for pb::ProveResponse {
    fn from(res: ServerResult) -> Self {
        match res {
            ServerResult::ForValidate(resp) => Self {
                is_valid: resp.is_valid,
                error_msg: resp.error_msg,
                time_cost_secs: 0.0,
                proof: Vec::new(),
                inputs: Vec::new(),
            },
            ServerResult::ForProve(resp) => resp,
            _ => unreachable!(),
        }
    }
}

impl ServerResult {
    pub fn new(for_validate: bool) -> Self {
        match for_validate {
            true => Self::ForValidate(pb::ValidateResponse {
                is_valid: false,
                error_msg: String::new(),
            }),
            false => Self::ForProve(pb::ProveResponse {
                is_valid: false,
                error_msg: String::new(),
                time_cost_secs: 0.0,
                proof: Vec::new(),
                inputs: Vec::new(),
            }),
        }
    }

    pub fn success(self) -> Self {
        match self {
            Self::ForValidate(mut inner) => {
                inner.is_valid = true;
                inner.error_msg = String::new();
                Self::ForValidate(inner)
            }
            Self::ForProve(mut inner) => {
                inner.is_valid = true;
                inner.error_msg = String::new();
                Self::ForProve(inner)
            }
            Self::Error(_) => unreachable!(),
        }
    }

    pub fn any_error<T, E>(err_ret: Result<T, E>) -> Self
    where
        T: std::fmt::Debug,
        E: std::fmt::Display,
    {
        Self::Error(ErrDetail {
            is_valid: false,
            error_msg: format!("{}", err_ret.unwrap_err()),
        })
    }
}

type ServerResultNotify = oneshot::Sender<ServerResult>;
type ServerRequest = (pb::Request, bool, ServerResultNotify);
pub type ServerCore = Box<dyn Fn(Vec<u8>, bool) -> ServerResult + Send>;

pub struct ServerOptions {
    pub server_addr: Option<String>,
    pub build_core: Box<dyn FnOnce() -> ServerCore + Send>,
}

struct GrpcHandler {
    tasks: Arc<Mutex<VecDeque<ServerRequest>>>,
    cur_task: Arc<Mutex<Option<String>>>,
    req_sender: mpsc::Sender<ServerRequest>,
}

impl ServerOptions {
    fn build_server(&self, req_sender: mpsc::Sender<ServerRequest>) -> GrpcHandler {
        GrpcHandler {
            tasks: Arc::new(Mutex::new(VecDeque::with_capacity(32))),
            cur_task: Arc::new(Mutex::new(None)),
            req_sender,
        }
    }
}

async fn schedule_task(
    mut notify: mpsc::Receiver<ServerRequest>,
    tasks: Arc<Mutex<VecDeque<ServerRequest>>>,
    cur_task_id: Arc<Mutex<Option<String>>>,
    core_build: Box<dyn FnOnce() -> ServerCore + Send>,
) {
    let mut server_task_h = tokio::task::spawn_blocking(move || {
        log::info!("Building sever core ...");
        let core = core_build();
        log::info!("Building sever core done");
        core
    });

    loop {
        let is_task_active = cur_task_id.lock().await.is_some() || !tasks.lock().await.is_empty();

        tokio::select! {
            h_ret = &mut server_task_h, if is_task_active => {

                //if joinerror, we are over
                let core = h_ret.unwrap();

                let last = match tasks.lock().await.pop_back() {
                    Some((req, valid_only, notify)) => {
                        let last_cur = cur_task_id.lock().await.replace(req.task_id.clone());
                        log::debug!("Trigger handling new task {}", req.task_id);

                        //DO prove/valid task
                        server_task_h = tokio::task::spawn_blocking(move||{
                            if notify.send(core(req.witness, valid_only)).is_err(){
                                log::warn!("Send task {} result failure", req.task_id);
                            }
                            core
                        });

                        last_cur
                    },
                    _ => {
                        //put the core into joinhandle ("The Sword in the Stone")
                        server_task_h = tokio::task::spawn_blocking(move||{core});
                        cur_task_id.lock().await.take()
                    }
                };

                if let Some(task_id) = last {
                    log::info!("Task {} is proven", task_id);
                }
            }
            Some(newtask) = notify.recv() => {
                log::debug!("Receive new task {}", newtask.0.task_id);
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
    async fn prove(&self, request: tonic::Request<pb::Request>) -> Result<tonic::Response<pb::ProveResponse>, tonic::Status> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.req_sender.send((request.into_inner(), false, tx)).await {
            return Err(tonic::Status::internal(format!("send prove request fail: {}", e)));
        }

        match rx.await {
            Ok(ServerResult::ForProve(ret)) => Ok(tonic::Response::new(ret)),
            Ok(_) => Err(tonic::Status::internal("server core return unmatched ret type")),
            Err(e) => Err(tonic::Status::internal(format!("recv server response fail: {}", e))),
        }
    }
    async fn validate_witness(&self, request: tonic::Request<pb::Request>) -> Result<tonic::Response<pb::ValidateResponse>, tonic::Status> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.req_sender.send((request.into_inner(), true, tx)).await {
            return Err(tonic::Status::internal(format!("send prove request fail: {}", e)));
        }

        match rx.await {
            Ok(ServerResult::ForValidate(ret)) => Ok(tonic::Response::new(ret)),
            Ok(_) => Err(tonic::Status::internal("server core return unmatched ret type")),
            Err(e) => Err(tonic::Status::internal(format!("recv server response fail: {}", e))),
        }
    }
    async fn status(&self, _request: tonic::Request<pb::EmptyRequest>) -> Result<tonic::Response<pb::StatusResponse>, tonic::Status> {
        let cur = self.cur_task.lock().await;
        Ok(tonic::Response::new(pb::StatusResponse {
            avaliable: cur.is_none(),
            current_task_id: cur.as_ref().map(String::clone).unwrap_or_else(String::new),
        }))
    }
}

use futures::future::TryFutureExt;

pub fn run(opt: ServerOptions) {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime")
        .block_on(async move {
            //just set a magic number because we always keep pumping request
            let (tx, rx) = mpsc::channel(16);
            let svr = opt.build_server(tx);
            let addr = opt.server_addr.unwrap_or_else(|| String::from("0.0.0.0:50055"));
            let buildcore = opt.build_core;
            log::info!("Starting grpc server at {}", addr);

            let tasks_scheduled = svr.tasks.clone();
            let status_scheduled = svr.cur_task.clone();
            let scheduler = tokio::spawn(async move {
                schedule_task(rx, tasks_scheduled, status_scheduled, buildcore).await;
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
