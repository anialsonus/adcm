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
import { Component, EventEmitter, Input, Output } from '@angular/core';

@Component({
  selector: 'app-add-controls',
  template: `
    <p class="controls">
      <button mat-raised-button color="primary" (click)="oncancel()">Cancel</button>
      <span class="example-spacer"></span>
      <button mat-raised-button [disabled]="disabled" color="accent" (click)="onsave()">Save</button>
    </p>
  `,
  styles: []
})
export class ControlsComponent {
  @Input() disabled: boolean;
  @Output() cancel = new EventEmitter();
  @Output() save = new EventEmitter();

  oncancel() {
    this.cancel.emit();
  }

  onsave() {
    this.save.emit();
  }
}
