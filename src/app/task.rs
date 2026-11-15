use std::sync::mpsc::{self, Receiver, TryRecvError};

pub(super) struct Task<T, E> {
    receiver: Option<Receiver<Result<T, E>>>,
}

impl<T, E> Default for Task<T, E> {
    fn default() -> Self {
        Self { receiver: None }
    }
}

impl<T: Send + 'static, E: Send + 'static> Task<T, E> {
    /// Runs an operation and requests repaint when its result is ready.
    pub(super) fn start(
        &mut self,
        ctx: &egui::Context,
        operation: impl FnOnce() -> Result<T, E> + Send + 'static,
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
    pub(super) fn poll(&mut self) -> Option<Result<T, TaskError<E>>> {
        let result = match self.receiver.as_ref()?.try_recv() {
            Ok(result) => result.map_err(TaskError::Operation),
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Err(TaskError::Stopped),
        };
        self.receiver = None;
        Some(result)
    }
}

#[derive(Debug)]
pub(super) enum TaskError<E> {
    Operation(E),
    Stopped,
}

impl<E: std::fmt::Display> std::fmt::Display for TaskError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operation(error) => std::fmt::Display::fmt(error, f),
            Self::Stopped => f.write_str("Background operation stopped"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for TaskError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Operation(error) => Some(error),
            Self::Stopped => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factr_core::error::RecoveryError;

    #[test]
    fn preserves_typed_errors_and_reports_a_disconnected_worker() {
        let mut task: Task<(), RecoveryError> = Task::default();
        task.start(&egui::Context::default(), || {
            Err(RecoveryError::InvalidFormat)
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let result = loop {
            if let Some(result) = task.poll() {
                break result;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        };
        assert!(matches!(
            result,
            Err(TaskError::Operation(RecoveryError::InvalidFormat))
        ));
        assert!(!task.is_busy());
        let (sender, receiver) = mpsc::channel();
        task.receiver = Some(receiver);
        drop(sender);
        assert!(matches!(task.poll(), Some(Err(TaskError::Stopped))));
        assert!(!task.is_busy());
    }
}
