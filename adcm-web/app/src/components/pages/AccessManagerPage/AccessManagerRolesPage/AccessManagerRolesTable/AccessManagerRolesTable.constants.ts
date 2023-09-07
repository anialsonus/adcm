import { TableColumn } from '@uikit';

export const columns: TableColumn[] = [
  {
    label: 'Name',
    name: 'name',
    isSortable: true,
  },
  {
    label: 'Description',
    name: 'description',
  },
  {
    label: 'Permissions',
    name: 'permissions',
  },
  {
    label: '',
    name: '',
    width: '80px',
  },
  {
    label: 'Actions',
    name: 'actions',
    headerAlign: 'center',
    width: '100px',
  },
];
