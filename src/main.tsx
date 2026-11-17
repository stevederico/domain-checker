import './assets/styles.css';
import { useEffect } from 'react';
import { Toaster } from 'sonner';
import { createSkateboardApp } from '@stevederico/skateboard-ui/App';
import type { AppRoute } from '@stevederico/skateboard-ui/App';
import { useSafeNavigate } from '@stevederico/skateboard-ui/Utilities';
import Layout from '@stevederico/skateboard-ui/Layout';
import constants from './constants.json';
import HomeView from './components/HomeView';
import CommandMenu from './components/CommandMenu';

function AppLayout() {
  return (
    <>
      <CommandMenu />
      <Layout />
      <Toaster theme="system" position="bottom-center" />
    </>
  );
}

function LandingRedirect() {
  const navigate = useSafeNavigate();
  useEffect(() => {
    navigate('/app/home', { replace: true });
  }, [navigate]);
  return null;
}

const appRoutes: AppRoute[] = [
  { path: 'home', element: <HomeView /> },
];

createSkateboardApp({
  constants,
  appRoutes,
  defaultRoute: 'home',
  landingPage: <LandingRedirect />,
  overrides: { layout: AppLayout },
  loadLegal: () => import('./legal.json'),
});
