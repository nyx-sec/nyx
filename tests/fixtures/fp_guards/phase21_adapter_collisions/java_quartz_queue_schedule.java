import org.quartz.Job;
import org.quartz.JobExecutionContext;

class TickJob implements Job {
  public void execute(JobExecutionContext context) {}

  public void enqueue(Object payload) {
    NotificationQueue queue = new NotificationQueue();
    queue.scheduleJob(payload);
  }
}

class NotificationQueue {
  void scheduleJob(Object payload) {}
}
