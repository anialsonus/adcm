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
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { ApiService } from '@app/core/api';
import { ICluster } from '@app/models/cluster';
import { MaterialModule } from '@app/shared/material.module';
import { StuffModule } from '@app/shared/stuff.module';

import { IDetails, NavigationService } from '../navigation.service';
import { TopComponent } from './top.component';
import { of } from 'rxjs/internal/observable/of';
import { Upgrade } from '@app/shared/components';


const response: Upgrade[] = [
  {
    bundle_id: 1,
    description: '',
    do: '',
    from_edition: [],
    id: 1,
    license: 'absent',
    license_url: '',
    max_strict: false,
    max_version: '',
    min_strict: false,
    min_version: '',
    name: '',
    state_available: '',
    state_on_success: '',
    upgradable: true,
    url: '',
  }
];

describe('TopComponent', () => {
  let component: TopComponent;
  let fixture: ComponentFixture<TopComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [MaterialModule, StuffModule, RouterTestingModule],
      declarations: [TopComponent],
      providers: [NavigationService, { provide: ApiService, useValue: { get: () => of(response) } }],
    }).compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(TopComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('breadcrumbs for item without cluster (parent) should contains full path (app->item_type->item_name)', () => {
    component.current = { name: 'host_test', typeName: 'host', id: 1, issue: {} } as IDetails;
    fixture.detectChanges();
    const links = fixture.nativeElement.querySelectorAll('app-crumbs mat-nav-list a');
    // app -- hosts -- host_test
    expect(links.length).toBe(3);
  });

  it('breadcrumbs for service (item with cluster - parent) should contains full path (app->clusters->cluster_name->services->service_name)', () => {
    component.current = {
      name: 'service_test',
      typeName: 'service',
      id: 1,
      issue: {},
      parent: { id: 1, name: 'cluster_test', issue: {} } as ICluster
    } as IDetails;
    fixture.detectChanges();
    const links = fixture.nativeElement.querySelectorAll('app-crumbs mat-nav-list a');
    // app -- clusters -- cluster_tes -- services -- service_test
    expect(links.length).toBe(5);
  });

  it('previous element for current in the breadcrumbs should have to name `[current.typeName]s`', () => {
    component.current = {
      name: 'service_test',
      typeName: 'service',
      id: 1,
      issue: {},
      parent: { id: 1, name: 'cluster_test', issue: {}, typeName: 'cluster' }
    } as IDetails;
    fixture.detectChanges();
    const links = fixture.nativeElement.querySelectorAll('app-crumbs mat-nav-list a');
    // app -- clusters -- cluster_tes -- services -- service_test
    expect(links[1].innerText).toBe('CLUSTERS');
    expect(links[3].innerText).toBe('SERVICES');
  });

  it('if item contains issue should show icon <priority_hight>', () => {
    component.current = {
      name: 'service_test',
      typeName: 'service',
      id: 1,
      issue: {},
      parent: <unknown>{ id: 1, name: 'cluster_test', issue: { config: false }, typeName: 'cluster' },
    } as IDetails;
    fixture.detectChanges();
    const cluster_link = fixture.nativeElement.querySelector('app-crumbs mat-nav-list a[href="/cluster/1"]');
    expect(cluster_link).toBeTruthy();
    const icon = cluster_link.nextSibling;
    expect(icon).toBeTruthy();
    expect(icon.tagName).toBe('MAT-ICON');
    expect(icon.innerText).toBe('priority_hight');
  });

  it('if item does not contains issue should hide icon <priority_hight>', () => {
    component.current = {
      name: 'service_test',
      typeName: 'service',
      id: 1,
      issue: {},
      parent: <unknown>{ id: 1, name: 'cluster_test', issue: { config: false }, typeName: 'cluster' },
    } as IDetails;
    fixture.detectChanges();
    const cluster_link = fixture.nativeElement.querySelector('app-crumbs mat-nav-list a[href="/cluster/1"]');

    const icon = cluster_link.nextSibling;
    expect(icon).toBeTruthy();
    expect(icon.tagName).toBe('MAT-ICON');
    expect(icon.innerText).toBe('priority_hight');

    component.isIssue = false;
    fixture.detectChanges();
    const icon2 = cluster_link.nextSibling;
    expect(icon2.tagName).not.toBe('MAT-ICON');
    expect(icon2.innerText).not.toBe('priority_hight');
  });

  it('if item contains upgradable should show button upgade', () => {
    component.current = {
      name: 'cluster_test',
      typeName: 'cluster',
      id: 1,
      upgradable: true,
    } as IDetails;

    fixture.detectChanges();

    const up_btn = fixture.nativeElement.querySelector('app-upgrade button[adcm_test=upgrade_btn]');
    expect(up_btn).toBeTruthy();
  });

  it('if item does not contain upgradable should hide button upgade', () => {
    component.current = {
      name: 'cluster_test',
      typeName: 'cluster',
      id: 1,
      upgradable: true,
    } as IDetails;

    fixture.detectChanges();

    const up_btn = fixture.nativeElement.querySelector('app-upgrade button[adcm_test=upgrade_btn]');
    expect(up_btn).toBeTruthy();

    component.upgradable = false;
    fixture.detectChanges();
    const up_btn2 = fixture.nativeElement.querySelector('app-upgrade button[adcm_test=upgrade_btn]');
    expect(up_btn2).toBeFalsy();
  });
});
