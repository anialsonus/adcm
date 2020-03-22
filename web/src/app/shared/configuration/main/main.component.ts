// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import { animate, state, style, transition, trigger } from '@angular/animations';
import { AfterViewChecked, ChangeDetectionStrategy, ChangeDetectorRef, Component, Input, OnInit, ViewChild } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { ClusterService } from '@app/core';
import { ApiService } from '@app/core/api';
import { EventMessage, SocketState } from '@app/core/store';
import { SocketListenerDirective } from '@app/shared/directives';
import { Store } from '@ngrx/store';
import { Observable, of } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';

import { FieldService, IToolsEvent } from '../field.service';
import { ConfigFieldsComponent } from '../fields/fields.component';
import { HistoryComponent } from '../tools/history.component';
import { ToolsComponent } from '../tools/tools.component';
import { IConfig } from '../types';

@Component({
  selector: 'app-config-form',
  templateUrl: './main.component.html',
  styleUrls: ['./main.component.scss'],
  animations: [
    trigger('history', [
      state('hide', style({ top: '130px' })),
      state('show', style({ top: '200px' })),
      state('hideTools', style({ opacity: 0 })),
      state('showTools', style({ opacity: 0.8 })),
      transition('hideTools => showTools', animate('.5s .3s ease-in')),
      transition('showTools => hideTools', animate('.2s ease-out')),
      transition('hide <=> show', animate('.3s'))
    ])
  ],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class ConfigComponent extends SocketListenerDirective implements OnInit, AfterViewChecked {
  loadingStatus = 'Loading...';
  config$: Observable<IConfig>;
  rawConfig: IConfig;

  saveFlag = false;
  historyShow = false;

  isLock = false;

  private _url = '';

  @ViewChild('fields') fields: ConfigFieldsComponent;
  @ViewChild('history') historyComponent: HistoryComponent;
  @ViewChild('tools') tools: ToolsComponent;

  @Input()
  set configUrl(url: string) {
    this._url = url;
    this.config$ = this.getConfig();
  }

  get historyUrl(): string {
    return `${this._url}history/`;
  }

  constructor(
    private api: ApiService,
    private current: ClusterService,
    private cdRef: ChangeDetectorRef,
    private service: FieldService,
    socket: Store<SocketState>
  ) {
    super(socket);
  }

  ngOnInit() {
    if (!this._url && this.current.Current) {
      this.configUrl = this.current.Current.config;
    }

    super.startListenSocket();
  }

  ngAfterViewChecked(): void {
    this.stub();
  }

  isAdvanced(data: IConfig) {
    return data.config.some(a => a.ui_options && a.ui_options.advanced);
  }

  toolsEvent(toolsEvent: IToolsEvent) {
    this[toolsEvent.name](toolsEvent.conditions);
  }

  fieldsEvents(e: { name: 'load'; data: { form: FormGroup } }) {
    if (e.name === 'load') {
      this.stub();
    }
  }

  get formValid() {
    return this.fields.form.valid;
  }

  history(flag: boolean) {
    this.historyShow = flag;
  }

  filter(c: { advanced: boolean; search: string }) {
    this.service.filterApply(this.fields.dataOptions, c);
    this.stub();
  }

  /**
   * change detection on manual
   */
  stub() {
    if (this.fields) {
      this.fields.checkForm();
      this.cdRef.detectChanges();
    }
  }

  socketListener(m: EventMessage) {
    if (this.current.Current && m.object.type === this.current.Current.typeName && m.object.id === this.current.Current.id && !this.saveFlag) {
      if (m.event === 'change_config' || m.event === 'change_state') {
        // TODO: magic literal string, maybe need use stateType
        this.isLock = m.object.details.value === 'locked';
        this.config$ = this.getConfig();
        this.cdRef.detectChanges();
      }
    }
  }

  getConfig() {
    return this.api.get<IConfig>(`${this._url}current/`).pipe(
      tap(c => {
        this.rawConfig = c;
        if (!c || !Object.keys(c).length || !c.config.length) this.loadingStatus = 'No configs.';
      }),
      catchError(() => {
        this.loadingStatus = 'Loading error.';
        return of(null);
      })
    );
  }

  save() {
    const form = this.fields.form;
    if (form.valid) {
      this.saveFlag = true;

      const config = this.service.parseValue(this.fields.form, this.rawConfig.config),
        attr = this.rawConfig.attr,
        description = this.tools.descriptionFormControl.value;

      const send = { config };
      if (attr) send['attr'] = attr;
      if (description) send['description'] = description;

      this.api
        .post<IConfig>(this.historyUrl, send)
        .pipe(this.takeUntil())
        .subscribe(c => {
          this.saveFlag = false;
          /**
           * TODO: history does not update!
           *  => need the new this.field.dataOptions
           */
          this.historyComponent.versionID = c.id;
          this.historyComponent.getData();
          this.cdRef.detectChanges();
        });
    } else {
      Object.keys(form.controls).forEach(controlName => form.controls[controlName].markAsTouched());
    }
  }

  changeVersion(a: { id: number }) {
    this.config$ = this.api.get<IConfig>(`${this.historyUrl}${a.id}/`);
  }
}
