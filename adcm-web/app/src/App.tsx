import React from 'react';
import { Provider } from 'react-redux';
import './scss/app.scss';
import { store } from '@store';
import { BrowserRouter, Navigate, Outlet, Route, Routes } from 'react-router-dom';
import LoginPage from '@pages/LoginPage/LoginPage';
import ClustersPage from '@pages/ClustersPage/ClustersPage';
import HostProvidersPage from '@pages/HostProvidersPage/HostProvidersPage';
import HostsPage from '@pages/HostsPage/HostsPage';
import JobsPage from '@pages/JobsPage/JobsPage';
import AccessManagerPage from '@pages/AccessManagerPage/AccessManagerPage';
import AuditPageLayout from '@layouts/AuditPageLayout/AuditPageLayout';
import AuditOperationsPage from '@pages/audit/AuditOperationsPage/AuditOperationsPage';
import AuditLoginsPage from '@pages/audit/AuditLoginsPage/AuditLoginsPage';
import BundlesPage from '@pages/BundlesPage/BundlesPage';
import PrivateResource from '@commonComponents/PrivateResource/PrivateResource';
import MainLayout from '@layouts/MainLayout/MainLayout';
import ProfilePage from '@pages/ProfilePage/ProfilePage';
import SettingsPage from '@pages/SettingsPage/SettingsPage';
import UserSession from '@commonComponents/UserSession/UserSession';
import ClusterPageLayout from '@layouts/ClusterPageLayout/ClusterPageLayout';

import {
  ClusterConfiguration,
  ClusterHosts,
  ClusterImport,
  ClusterMapping,
  ClusterOverview,
  ClusterServices,
} from '@pages/cluster';

function App() {
  return (
    <BrowserRouter>
      <Provider store={store}>
        <UserSession>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
              path="/"
              element={
                <PrivateResource>
                  <MainLayout>
                    <Outlet />
                  </MainLayout>
                </PrivateResource>
              }
            >
              <Route index element={<Navigate to="/clusters" replace />} />

              <Route path="/clusters">
                <Route index element={<ClustersPage />} />
                <Route path="/clusters/:clusterId" element={<ClusterPageLayout />}>
                  <Route index element={<Navigate to="overview" replace />} />
                  <Route path="/clusters/:clusterId/overview" element={<ClusterOverview />} />
                  <Route path="/clusters/:clusterId/services" element={<ClusterServices />} />
                  <Route path="/clusters/:clusterId/hosts" element={<ClusterHosts />} />
                  <Route path="/clusters/:clusterId/mapping" element={<ClusterMapping />} />
                  <Route path="/clusters/:clusterId/configuration" element={<ClusterConfiguration />} />
                  <Route path="/clusters/:clusterId/import" element={<ClusterImport />} />
                </Route>
              </Route>

              <Route path="/hostproviders" element={<HostProvidersPage />} />
              <Route path="/hosts" element={<HostsPage />} />
              <Route path="/jobs" element={<JobsPage />} />
              <Route path="/access-manager" element={<AccessManagerPage />} />
              <Route path="/audit" element={<AuditPageLayout />}>
                <Route index element={<Navigate to="/audit/operations" replace />} />
                <Route path="/audit/operations" element={<AuditOperationsPage />} />
                <Route path="/audit/logins" element={<AuditLoginsPage />} />
              </Route>
              <Route path="/bundles" element={<BundlesPage />} />
              <Route path="/profile" element={<ProfilePage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>
          </Routes>
        </UserSession>
      </Provider>
    </BrowserRouter>
  );
}

export default App;
