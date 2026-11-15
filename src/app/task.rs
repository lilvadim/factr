use std::sync::mpsc::{self, Receiver, TryRecvError};

pub(super) struct Task<T> {
    receiver: Option<Receiver<Result<T, String>>>,
}

impl<T> Default for Task<T> {
    fn default() -> Self {
        Self { receiver: None }
    }
}

impl<T: Send + 'static> Task<T> {
    /// Runs an operation and requests repaint when its result is ready.
    pub(super) fn start(
        &mut self,
        ctx: &egui::Context,
        operation: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) {
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        self.receiver = Some(receiver);
        std::thread::spawn(move || {
            let _ = sender.send(operation());
            ctx.request_repaint();
        });
    }

    /// Reports whether an operation is awaiting completion.
    pub(super) fn is_busy(&self) -> bool {
        self.receiver.is_some()
    }

    /// Takes one completed result without blocking.
    pub(super) fn poll(&mut self) -> Option<Result<T, String>> {
        let result = match self.receiver.as_ref()?.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Err("Background operation stopped".to_string()),
        };
        self.receiver = None;
        Some(result)
    }
}
