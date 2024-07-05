import { useDispatch, useRequestTimer, useDebounce, useStore } from '@hooks';
import { defaultDebounceDelay } from '@constants';
import { useParams } from 'react-router-dom';
import { useEffect } from 'react';
import {
  cleanupClusterHost,
  getClusterHost,
  getClusterHostComponentsStates,
} from '@store/adcm/cluster/hosts/host/clusterHostSlice';
import { loadClusterHostsDynamicActions } from '@store/adcm/cluster/hosts/hostsDynamicActionsSlice';
import { isBlockingConcernPresent } from '@utils/concernUtils';

export const useRequestClusterHost = () => {
  const dispatch = useDispatch();
  const { clusterId: clusterIdFromUrl, hostId: hostIdFromUrl } = useParams();
  const clusterId = Number(clusterIdFromUrl);
  const hostId = Number(hostIdFromUrl);
  const clusterHost = useStore(({ adcm }) => adcm.clusterHost.clusterHost);
  const accessCheckStatus = useStore(({ adcm }) => adcm.clusterHost.accessCheckStatus);

  useEffect(() => {
    return () => {
      dispatch(cleanupClusterHost());
    };
  }, [dispatch]);

  useEffect(() => {
    if (clusterHost && !isBlockingConcernPresent(clusterHost.concerns)) {
      dispatch(loadClusterHostsDynamicActions({ clusterId, hosts: [clusterHost] }));
    }
  }, [dispatch, clusterId, clusterHost, clusterHost?.concerns]);

  const debounceGetClusterHostData = useDebounce(() => {
    if (clusterId && hostId) {
      const payload = { clusterId, hostId };
      dispatch(getClusterHost(payload));
      dispatch(getClusterHostComponentsStates(payload));
    }
  }, defaultDebounceDelay);

  useRequestTimer(debounceGetClusterHostData, () => {}, 0, [clusterId, hostId]);

  return {
    accessCheckStatus,
  };
};
