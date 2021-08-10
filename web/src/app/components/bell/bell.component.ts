import { AfterViewInit, Component, ElementRef, Renderer2, ViewChild } from '@angular/core';
import { BaseDirective } from '@adwp-ui/widgets';
import { BehaviorSubject, combineLatest, interval, Observable, zip } from 'rxjs';
import { filter, map, mergeMap, take, takeWhile } from 'rxjs/operators';

import { TaskService } from '@app/services/task.service';
import { ACKNOWLEDGE_EVENT, NotificationsComponent } from '@app/components/notifications/notifications.component';
import { Task, TaskRaw } from '@app/core/types';
import { EventMessage, ProfileService } from '@app/core/store';
import { Stats, StatsService } from '@app/services/stats.service';

const RUNNING_COLOR = '#FFEA00';
const SUCCESS_COLOR = '#1EE564';
const FAILED_COLOR = '#FF8A80';

export interface NotificationsData {
  runningCount: number;
  successCount: number;
  failedCount: number;
}

@Component({
  selector: 'app-bell',
  template: `
    <div
      appPopover
      [component]="NotificationsComponent"
      [event]="bindedPopoverEvent"
      [data]="{ counts: counts, tasks: tasks }"
      class="bell-wrapper"
    >
      <div
        class="circle"
        [ngStyle]="{ background: bellGradient }"
        routerLink="/task"
      >
        <div class="animation hide" (animationstart)="onAnimationStart()" (animationend)="onAnimationEnd()" #animation></div>
        <div class="insider">
          <mat-icon>notifications</mat-icon>
        </div>
      </div>
    </div>
  `,
  styleUrls: ['./bell.component.scss']
})
export class BellComponent extends BaseDirective implements AfterViewInit {

  NotificationsComponent = NotificationsComponent;

  @ViewChild('animation', { static: false }) animationRef: ElementRef;

  runningCount = new BehaviorSubject<number>(0);
  successCount = new BehaviorSubject<number>(0);
  failedCount = new BehaviorSubject<number>(0);

  bellGradient = '';

  isAnimationRunning = new BehaviorSubject<boolean>(false);
  animationElem = new BehaviorSubject<Element>(null);

  counts = new BehaviorSubject<NotificationsData>(null);
  tasks = new BehaviorSubject<TaskRaw[]>([]);

  readonly bindedPopoverEvent = this.popoverEvent.bind(this);

  constructor(
    private taskService: TaskService,
    private renderer: Renderer2,
    private profileService: ProfileService,
    private statsService: StatsService,
  ) {
    super();
  }

  popoverEvent(event: any) {
    if (event === ACKNOWLEDGE_EVENT) {
      const lastTaskId = this.tasks.value[0]?.id;
      if (lastTaskId) {
        this.profileService.setLastViewedTask(lastTaskId).subscribe();
      }
      this.tasks.next([]);
      this.successCount.next(0);
      this.runningCount.next(0);
      this.failedCount.next(0);
      this.afterCountChanged(false);
    }
  }

  onAnimationStart() {
    this.isAnimationRunning.next(true);
  }

  onAnimationEnd() {
    this.isAnimationRunning.next(false);
  }

  startAnimation() {
    if (this.animationElem.value && !this.isAnimationRunning.value) {
      this.renderer.removeClass(this.animationElem.value, 'hide');
      this.renderer.addClass(this.animationElem.value, 'animated');
    }
  }

  endAnimation() {
    if (this.animationElem.value) {
      this.renderer.addClass(this.animationElem.value, 'hide');
      this.renderer.removeClass(this.animationElem.value, 'animated');
    }
  }

  afterCountChanged(animationNeeds = true) {
    const total =  this.runningCount.value + this.successCount.value + this.failedCount.value;
    if (total > 0) {
      const degOne = 360 / total;
      const degRunning = this.runningCount.value * degOne;
      const degSuccess = this.successCount.value * degOne;
      this.bellGradient =
        `conic-gradient(`
        + `${RUNNING_COLOR} 0deg ${degRunning}deg,`
        + `${SUCCESS_COLOR} ${degRunning}deg ${degRunning + degSuccess}deg,`
        + `${FAILED_COLOR} ${degRunning + degSuccess}deg 360deg)`;
    } else {
      this.bellGradient = 'transparent';
    }
    if (animationNeeds) {
      this.startAnimation();
    }
  }

  getChangeTaskObservable(): Observable<EventMessage> {
    return this.taskService.events(['change_job_status']).pipe(this.takeUntil());
  }

  decRunningCount() {
    const runningCount = this.runningCount.value - 1;
    this.runningCount.next(runningCount < 0 ? 0 : runningCount);
  }

  listenToJobs() {
    this.getChangeTaskObservable().subscribe((event) => {
      const status = event.object.details.value;
      if (status === 'running') {
        this.runningCount.next(this.runningCount.value + 1);
        this.afterCountChanged();
      } else if (status === 'success') {
        this.successCount.next(this.successCount.value + 1);
        this.decRunningCount();
        this.afterCountChanged();
      } else if (status === 'failed') {
        this.failedCount.next(this.failedCount.value + 1);
        this.decRunningCount();
        this.afterCountChanged();
      }
    });

    this.getChangeTaskObservable().pipe(
      filter(event => event.object.details.type === 'status'),
      filter(event => event.object.details.value !== 'created'),
    ).subscribe((event) => {
      const tasks: TaskRaw[] = this.tasks.value.slice();
      const index = tasks.findIndex(item => item.id === event.object.id);
      if (index >= 0) {
        const task: TaskRaw = Object.assign({}, tasks[index]);
        task.status = event.object.details.value;
        tasks.splice(index, 1, task);
        this.tasks.next(tasks);
      } else {
        this.taskService.get(event.object.id).subscribe((task) => {
          task.status = event.object.details.value;
          tasks.unshift(task);
          this.tasks.next(tasks.slice(0, 5));
        });
      }
    });
  }

  getCurrentCounts(): Observable<Stats> {
    return this.profileService.getProfile().pipe(
      take(1),
      mergeMap((user) => this.statsService.tasks(user.profile?.lastViewedTask?.id)),
    );
  }

  getLastTasks(): Observable<Task[]> {
    return zip(
      this.taskService.list({ ordering: '-finish_date', status: 'failed', limit: '5' }),
      this.taskService.list({ ordering: '-finish_date', status: 'success', limit: '5' }),
      this.taskService.list({ ordering: '-start_date', status: 'running', limit: '5' }),
      this.profileService.getProfile(),
    ).pipe(map(([failed, succeed, running, user]) => {
      let tasks = [...failed.results, ...succeed.results, ...running.results].sort((a, b) => {
        const getDateField = (task: Task) => task.status === 'failed' || task.status === 'success' ? task.finish_date : task.start_date;
        const aDate = new Date(getDateField(a));
        const bDate = new Date(getDateField(b));
        return aDate.getDate() - bDate.getDate();
      }).slice(0, 5);

      if (user.profile?.lastViewedTask?.id) {
        tasks = tasks.filter(task => task.id > user.profile.lastViewedTask.id);
      }

      return tasks;
    }));
  }

  ngAfterViewInit(): void {
    interval(200).pipe(
      this.takeUntil(),
      takeWhile(() => !this.animationElem.value),
    ).subscribe(() => {
      this.animationElem.next(this.animationRef ? this.animationRef.nativeElement : null);
    });

    this.animationElem.pipe(
      this.takeUntil(),
      filter((elem) => !!elem),
      take(1),
    ).subscribe(() => {
      zip(this.getCurrentCounts(), this.getLastTasks())
        .subscribe(([stats, tasks]) => {
          this.runningCount.next(stats.running);
          this.successCount.next(stats.success);
          this.failedCount.next(stats.failed);
          this.afterCountChanged(!!(stats.running || stats.success || stats.failed));
          this.tasks.next(tasks);
          this.listenToJobs();
        });
    });

    this.isAnimationRunning.pipe(
      this.takeUntil(),
      filter(isRunning => !isRunning),
    ).subscribe(() => this.endAnimation());

    combineLatest(this.runningCount, this.successCount, this.failedCount)
    .pipe(this.takeUntil())
    .subscribe(
      ([runningCount, successCount, failedCount]) => this.counts.next({
        runningCount,
        successCount,
        failedCount,
      })
    );
  }

}
