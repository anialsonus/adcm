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
import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';
import { AuthGuard } from '@app/core';
import { DetailComponent } from '@app/shared/details/detail.component';
import { ConfigComponent } from '@app/shared/configuration/main/main.component';
import { MainInfoComponent, StatusComponent } from '@app/shared/components';
import { SharedModule } from '@app/shared/shared.module';

import { ListEntryComponent } from './list.component';
import { ActionCardComponent } from '@app/shared/components/actions/action-card/action-card.component';
import { HostproviderComponent } from '@app/components/hostprovider/hostprovider.component';
import { HostListComponent } from '@app/components/host-list/host-list.component';

const entryRouter = [
  {
    path: 'cluster',
    loadChildren: () => import('app/entry/cluster/cluster.module').then(m => m.ClusterModule),
  },
  {
    path: 'job',
    loadChildren: () => import('app/entry/job/job.module').then(m => m.JobModule),
  },
  {
    path: 'task',
    loadChildren: () => import('app/entry/task/task.module').then(m => m.TaskModule),
  },
  {
    path: 'bundle',
    loadChildren: () => import('app/entry/bundle/bundle.module').then(m => m.BundleModule),
  },
  {
    path: 'host',
    component: HostListComponent,
    canActivate: [AuthGuard],
  },
  {
    path: 'host/:host',
    component: DetailComponent,
    canActivate: [AuthGuard],
    children: [
      { path: '', redirectTo: 'main', pathMatch: 'full' },
      { path: 'main', component: MainInfoComponent },
      { path: 'config', component: ConfigComponent },
      { path: 'status', component: StatusComponent },
      { path: 'action', component: ActionCardComponent },
    ],
  },
  {
    path: 'cluster/:cluster/host/:host/provider/:provider',
    redirectTo: 'provider/:provider',
  },
  {
    path: 'host/:host/provider/:provider',
    redirectTo: 'provider/:provider',
  },
  {
    path: 'provider',
    canActivate: [AuthGuard],
    component: HostproviderComponent,
  },
  {
    path: 'provider/:provider',
    canActivate: [AuthGuard],
    component: DetailComponent,
    children: [
      { path: '', redirectTo: 'main', pathMatch: 'full' },
      { path: 'main', component: MainInfoComponent },
      { path: 'config', component: ConfigComponent },
      { path: 'action', component: ActionCardComponent },
    ],
  },
];

@NgModule({
  imports: [CommonModule, SharedModule, RouterModule.forChild(entryRouter)],
  declarations: [ListEntryComponent, HostproviderComponent, HostListComponent],
})
export class EntryModule {}
