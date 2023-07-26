import { useStore } from '@hooks';
import { setBreadcrumbs } from '@store/adcm/breadcrumbs/breadcrumbsSlice';
import React, { useEffect } from 'react';
import { useDispatch } from 'react-redux';

const ClusterOverview: React.FC = () => {
  const { cluster } = useStore((s) => s.adcm.cluster);
  const dispatch = useDispatch();

  useEffect(() => {
    if (cluster) {
      dispatch(
        setBreadcrumbs([
          { href: '/clusters', label: 'Clusters' },
          { href: `/clusters/${cluster.id}`, label: cluster.name },
          { label: 'Overview' },
        ]),
      );
    }
  }, [cluster, dispatch]);

  return (
    <div>
      <h1>Cluster Overview</h1>
    </div>
  );
};

export default ClusterOverview;
