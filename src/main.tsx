/**
 * Application entry point
 *
 * Configures routing and initializes app with skateboard-ui framework.
 * Single route for domain checker — no auth required.
 *
 * @see {@link https://github.com/stevederico/skateboard|Skateboard Docs}
 */
import './assets/styles.css';
import { useEffect } from 'react';
import { createSkateboardApp } from '@stevederico/skateboard-ui/App';
import type { AppRoute } from '@stevederico/skateboard-ui/App';
import { useSafeNavigate } from '@stevederico/skateboard-ui/Utilities';
import Layout from '@stevederico/skateboard-ui/Layout';
import constants from './constants.json';
import HomeView from './components/HomeView';
import CommandMenu from './components/CommandMenu';


/**
 * App layout with global command menu overlay.
 *
 * Wraps the default skateboard-ui Layout and injects CommandMenu
 * so the Cmd+K shortcut is available on all authenticated routes.
 *
 * @returns Layout with command menu
 */
function AppLayout() {
  return (
    <>
      <CommandMenu />
      <Layout />
    </>
  );
}

/**
 * Landing page for "/" — this app has no marketing page, so send visitors
 * straight to the checker.
 *
 * Uses the shell's useSafeNavigate rather than react-router's Navigate so the
 * app keeps no direct react-router dependency (skateboard-ui 5.x rule).
 *
 * @returns Nothing; redirects on mount
 */
function LandingRedirect() {
  const navigate = useSafeNavigate();
  useEffect(() => {
    navigate('/app/home', { replace: true });
  }, [navigate]);
  return null;
}

/**
 * Application route configuration
 *
 * Maps route paths to view components. Routes are relative to root (no leading slash).
 */
const appRoutes: AppRoute[] = [
  { path: 'home', element: <HomeView /> },
];

/**
 * Initialize and mount Skateboard app
 *
 * @param config - App configuration
 * @param config.constants - App constants from constants.json
 * @param config.appRoutes - Route configuration array
 * @param config.defaultRoute - Initial route path
 * @param config.loadLegal - Lazy loader for the legal bodies (src/legal.json)
 */
createSkateboardApp({
  constants,
  appRoutes,
  defaultRoute: 'home',
  landingPage: <LandingRedirect />,
  overrides: { layout: AppLayout },
  // Legal bodies stay out of the main chunk; routes load src/legal.json on demand.
  loadLegal: () => import('./legal.json'),
});
