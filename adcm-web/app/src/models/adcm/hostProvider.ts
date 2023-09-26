import { AdcmConcerns } from '@models/adcm/concern';

export interface AdcmHostProvider {
  id: number;
  name: string;
  prototype: AdcmHostProviderPrototype;
  state: string;
  multiState: string[];
  description: string;
  concerns: AdcmConcerns[];
  isUpgradable: boolean;
  mainInfo: string;
  cluster: AdcmHostProviderCluster;
}

export interface AdcmHostProviderCluster {
  id: number;
  name: string;
}

export interface AdcmHostProviderPrototype {
  name: string;
  displayName: string;
  version: string;
  type: string;
}

export interface AdcmHostProviderFilter {
  hostproviderName?: string;
  prototype?: string;
}

export interface AdcmHostProviderPayload {
  name: string;
  prototypeId: number;
  description: string;
}
