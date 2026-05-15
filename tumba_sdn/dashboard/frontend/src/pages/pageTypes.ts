import type { DashboardSnapshot } from '../api/types';

export type PageProps = {
  snapshot: DashboardSnapshot;
  refresh: () => void;
};
