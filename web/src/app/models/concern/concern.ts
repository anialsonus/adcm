import { Entity } from '@adwp-ui/widgets';
import { ConcernReason } from './concern-reason';

export type ConcernType = 'issue' | 'lock';

export interface Concern extends Entity {
  blocking: boolean;
  reason: ConcernReason;
  type: ConcernType;
  url?: string;
}
