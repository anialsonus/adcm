import { Directive } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { Store } from '@ngrx/store';
import { MatDialog } from '@angular/material/dialog';
import { MatCheckboxChange } from '@angular/material/checkbox';
import { Entity, IListResult } from '@adwp-ui/widgets';
import * as Immutable from 'immutable';
import { filter } from 'rxjs/operators';
import { zip } from 'rxjs';

import { ListService } from '@app/shared/components/list/list.service';
import { SocketState } from '@app/core/store';
import { DeletableEntityAbstractService } from '@app/abstract/deletable-entity.abstract.service';
import { DialogComponent } from '@app/shared/components';
import { AdwpListDirective } from './adwp-list.directive';

@Directive({
  selector: '[appRbacEntityList]',
})
export abstract class RbacEntityListDirective<T extends Entity> extends AdwpListDirective<T> {

  abstract getTitle(row: T): string;

  constructor(
    protected service: ListService,
    protected store: Store<SocketState>,
    public route: ActivatedRoute,
    public router: Router,
    public dialog: MatDialog,
    protected entityService: DeletableEntityAbstractService,
  ) {
    super(service, store, route, router, dialog);
  }

  chooseAll(event: MatCheckboxChange): void {
    const value: IListResult<T> = Immutable.fromJS(this.data$.value).toJS() as any;
    value.results.forEach((row: any) => row.checked = event.checked);
    this.data$.next(value);
  }

  deleteEntities(): void {
    const checkedItems = this.data$.value.results.filter((item: any) => item.checked);
    this.dialog
      .open(DialogComponent, {
        data: {
          title: checkedItems.length > 1 ? 'Deleting selected entries' : `Deleting  "${this.getTitle(checkedItems[0])}"`,
          text: 'Are you sure?',
          controls: ['Yes', 'No'],
        },
      })
      .beforeClosed()
      .pipe(filter((yes) => yes))
      .subscribe(() => {
        const rowsToDelete = this.data$.value.results.filter((row: any) => row.checked).map(row => this.entityService.delete(row.id));
        zip(...rowsToDelete).subscribe(() => this.baseListDirective.refresh());
      });
  }

}
