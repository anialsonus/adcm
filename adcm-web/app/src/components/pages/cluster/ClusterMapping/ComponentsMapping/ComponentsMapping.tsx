import { useMemo } from 'react';
import { AnchorBar, AnchorBarItem, AnchorList, MarkerIcon, Text } from '@uikit';
import { useClusterMapping } from '../useClusterMapping';
import ComponentContainer from './ComponentContainer/ComponentContainer';
import ClusterMappingToolbar from '../ClusterMappingToolbar/ClusterMappingToolbar';
import { serviceMarkerIcons } from './ComponentsMapping.constants';
import s from './ComponentsMapping.module.scss';
import cn from 'classnames';

const buildServiceAnchorId = (id: number) => `anchor_${id}`;

const ComponentsMapping = () => {
  const {
    hosts,
    servicesMapping,
    servicesMappingFilter,
    handleServicesMappingFilterChange,
    isMappingChanged,
    isValid,
    hasSaveError,
    handleMapHostsToComponent,
    handleUnmap,
    handleSave,
    handleRevert,
  } = useClusterMapping();

  const anchorItems: AnchorBarItem[] = useMemo(
    () =>
      servicesMapping.map((m) => ({
        label: m.service.displayName,
        id: buildServiceAnchorId(m.service.id),
      })),
    [servicesMapping],
  );

  const handleFilterChange = (hostName: string) => {
    handleServicesMappingFilterChange({ hostName });
  };

  return (
    <div className={s.componentsMapping}>
      <ClusterMappingToolbar
        className={s.componentsMapping__toolbar}
        filter={servicesMappingFilter.hostName}
        filterPlaceHolder="Search hosts"
        hasError={hasSaveError}
        isSaveDisabled={!isMappingChanged || !isValid}
        onSave={handleSave}
        onFilterChange={handleFilterChange}
        onRevert={handleRevert}
      />
      <div className={s.componentsMapping__content}>
        <div>
          {servicesMapping.map(({ service, componentsMapping, validationSummary }) => {
            const titleClassName = cn(s.serviceMapping__title, s[`serviceMapping__title_${validationSummary}`]);

            return (
              <div key={service.id} className={s.serviceMapping}>
                <Text className={titleClassName} variant="h2" id={buildServiceAnchorId(service.id)}>
                  {service.displayName}
                  <MarkerIcon type={serviceMarkerIcons[validationSummary]} size="medium" />
                </Text>
                {componentsMapping.map((componentMapping) => (
                  <ComponentContainer
                    key={componentMapping.component.id}
                    componentMapping={componentMapping}
                    allHosts={hosts}
                    onMap={handleMapHostsToComponent}
                    onUnmap={handleUnmap}
                  />
                ))}
              </div>
            );
          })}
        </div>
        <AnchorBar>
          <AnchorList items={anchorItems} />
        </AnchorBar>
      </div>
    </div>
  );
};

export default ComponentsMapping;
