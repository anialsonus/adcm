# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import TypeAlias

from core.types import ADCMCoreType, ExtraActionTargetType
from django.db.models import Model

from cm.models import ADCM, ActionHostGroup, Cluster, ClusterObject, Host, HostProvider, ServiceComponent

CoreObject: TypeAlias = Cluster | ClusterObject | ServiceComponent | HostProvider | Host


def core_type_to_model(core_type: ADCMCoreType) -> type[CoreObject | ADCM]:
    match core_type:
        case ADCMCoreType.CLUSTER:
            return Cluster
        case ADCMCoreType.SERVICE:
            return ClusterObject
        case ADCMCoreType.COMPONENT:
            return ServiceComponent
        case ADCMCoreType.HOSTPROVIDER:
            return HostProvider
        case ADCMCoreType.HOST:
            return Host
        case ADCMCoreType.ADCM:
            return ADCM
        case _:
            raise ValueError(f"Can't convert {core_type} to ORM model")


def core_type_to_db_record_type(core_type: ADCMCoreType) -> str:
    match core_type:
        case ADCMCoreType.CLUSTER:
            return "cluster"
        case ADCMCoreType.SERVICE:
            return "service"
        case ADCMCoreType.COMPONENT:
            return "component"
        case ADCMCoreType.HOSTPROVIDER:
            return "provider"
        case ADCMCoreType.HOST:
            return "host"
        case ADCMCoreType.ADCM:
            return "adcm"
        case _:
            raise ValueError(f"Can't convert {core_type} to type name in DB")


def db_record_type_to_core_type(db_record_type: str) -> ADCMCoreType:
    try:
        return ADCMCoreType(db_record_type)
    except ValueError:
        if db_record_type == "provider":
            return ADCMCoreType.HOSTPROVIDER

        raise


def model_name_to_core_type(model_name: str) -> ADCMCoreType:
    name_ = model_name.lower()
    try:
        return ADCMCoreType(name_)
    except ValueError:
        if name_ == "clusterobject":
            return ADCMCoreType.SERVICE

        if name_ == "servicecomponent":
            return ADCMCoreType.COMPONENT

        raise


def model_to_core_type(model: type[Model]) -> ADCMCoreType:
    return model_name_to_core_type(model_name=model.__name__)


def orm_object_to_core_type(object_: CoreObject) -> ADCMCoreType:
    return model_to_core_type(model=object_.__class__)


def model_to_action_target_type(model: type[Model]) -> ADCMCoreType | ExtraActionTargetType:
    if model == ActionHostGroup:
        return ExtraActionTargetType.ACTION_HOST_GROUP

    return model_to_core_type(model=model)


def orm_object_to_action_target_type(object_: CoreObject | ActionHostGroup) -> ADCMCoreType | ExtraActionTargetType:
    return model_to_action_target_type(model=object_.__class__)
