import type React from 'react';
import type { DashboardSnapshot } from '../api/types';
import { Header } from './Header';
import { Sidebar } from './Sidebar';

type LayoutProps = {
  snapshot: DashboardSnapshot;
  onRefresh: () => void;
  children: React.ReactNode;
};

export function Layout({ snapshot, onRefresh, children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-campus-bg">
      <Sidebar />
      <Header snapshot={snapshot} onRefresh={onRefresh} />
      <main className="px-4 py-5 lg:ml-64 lg:px-6">
        {children}
      </main>
    </div>
  );
}
