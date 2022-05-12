import { ComponentFixture, TestBed } from '@angular/core/testing';

import { MaintenanceModeButtonComponent } from './maintenance-mode-button.component';

describe('MaintenanceModeButtonComponent', () => {
  let component: MaintenanceModeButtonComponent<any>;
  let fixture: ComponentFixture<MaintenanceModeButtonComponent<any>>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ MaintenanceModeButtonComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(MaintenanceModeButtonComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
