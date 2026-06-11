/**
 * Application entry point
 *
 * Configures routing and initializes app with skateboard-ui framework.
 * Single route for domain checker — no auth required.
 *
 * @see {@link https://github.com/stevederico/skateboard|Skateboard Docs}
 */
import './assets/styles.css';
import { createSkateboardApp } from '@stevederico/skateboard-ui/App';
import type { AppRoute } from '@stevederico/skateboard-ui/App';
import { Navigate } from 'react-router';
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
 */
createSkateboardApp({
  constants,
  appRoutes,
  defaultRoute: 'home',
  landingPage: <Navigate to="/app/home" replace />,
  overrides: { layout: AppLayout }
});
