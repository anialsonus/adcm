Visual parts
############

Templates
=========

There are a number of different templates for different pages in ADCM. Check them all here:

.. _ui_templates_common:

Common
------

Main template of the application is the following:

.. image:: img/common_template.png

Template parts are:

* Main Menu - contains the following sections of ADCM:
 * :ref:`ui_templates_clusters`
 * Hostproviders
 * Hosts
 * Jobs
 * Bundles
 * Job states - displays information about the number of jobs in the process, success jobs, failed jobs.
 * Reference section - displays information about "Ask for help" and documentation.
 * User section - contains user profile settings, settings for working in ADCM, logout functionality from ADCM.
* Navigation Menu - displays decomposition to active/current section.
* Right Menu - pop-up window when selecting sections such as "Reference section", "User section". 
* Left Menu - contains the main sections when selecting a specific object (cluster, hostprovider, hosts etc)

.. note::
   TODO: We need to provide more information about parts.

Table View
----------

.. note::
   TODO: Describe table view here
   
.. _ui_templates_clusters:

Clusters
------

The cluster list template looks like this:

.. image:: img/cluster_template.png

Template parts are:

* Navigation Menu with an indication of the decomposition to the selected section.
* Button "Create cluster" - allows you to create a cluster.
* Tabular section which includes the following fields:
 * **Name** - contains information about the name of the cluster (sorting supported).
 * **Bundle** - contains information about the name of the :term:`Bundle` on the basis of which the cluster was added (sorting supported).
 * **Description** - contains additional information. Filled when adding a cluster.
 * **State** - contains information about the current state of the cluster (sorting supported).
 * **Status** - contains information about the current status of the cluster (sorting supported).
 * **Actions** - provides a choice of what action to perform on the cluster (install, start, stop).
 * **Import** - ???
 * **Upgrade** - allows to update the selected cluster.
 * **Config** - allows to go to the settings of the selected cluster.
* List of added clusters with information according to table fields.
* Button to delete an entry from the list of clusters
* Pagination of the list of clusters
       
.. _ui_templates_cluster-services:
       
Сluster services
------

The list of cluster services looks like this:

.. image:: img/cluster_services_template.png
 
Template parts are:

* Navigation Menu with an indication of the decomposition to the selected section, actions that can be performed on the cluster (start, stop, install, update).
* Cluster name information and link to cluster bundle.
* Button "Add services" - allows you to add services to the cluster.
* Left menu with the following sections (active partition is highlighted):
 * **Main**
 * **Services**
 * **Hosts**
 * **Host - Components**
 * **Configuration**
 * **Status**
 * **Import**
 * **Actions**
* Tabular section which includes the following fields:
 * **Name** - contains information about the name of the service (sorting supported).
 * **Version** - contains information about the version of the service.
 * **State** - contains information about the current state of the service (sorting supported).
 * **Status** - contains information about the current status of the service (sorting supported).
 * **Actions** - provides a choice of what action to perform on the service (check, expand, restart, shrink, start, stop).
 * **Import** - ???
 * **Config** - allows to go to the settings of the selected service.
* List of added services with information according to table fields.
* Pagination of the list of clusters

Forms
=====

.. _ui_elements_forms_login:

Login Form
----------

There are two variants of login form.

First is able to login over Google GAuth2.

.. image:: img/form_login_full.png


Second allows to login with user/password only.

.. image:: img/form_login_short.png

Input fields:

* **Login** - is an input to pass a username
* **Password** - is an input to pass a password. This field is protected and show no password actually.

Buttons:

* **Sign in with Google** - is a button that triggers GAuth2 login process
* **Login** - is a button which that triggers user/password login process

Create cluster
--------------

Upload Bundle
-------------
