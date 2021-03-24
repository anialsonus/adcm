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

import { SharedModule } from '@app/shared/shared.module';
import { JobInfoComponent } from './job-info.component';
import { JobRoutingModule } from './job-routing.module';
import { JobComponent, MainComponent } from './job.component';
import { LogComponent } from './log/log.component';
import { CheckComponent } from './log/check.component';
import { TextComponent } from './log/text.component';


@NgModule({
  declarations: [JobComponent, MainComponent, LogComponent, JobInfoComponent, CheckComponent, TextComponent],
  imports: [CommonModule, SharedModule, RouterModule, JobRoutingModule]
})
export class JobModule {}
