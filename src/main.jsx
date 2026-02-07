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
import { Navigate } from 'react-router-dom';
import constants from './constants.json';
import HomeView from './components/HomeView.jsx';


/**
 * Application route configuration
 * @type {Array<{path: string, element: JSX.Element}>}
 */
const appRoutes = [
  { path: 'home', element: <HomeView /> },
];

/**
 * Initialize and mount Skateboard app
 *
 * @param {Object} config - App configuration
 * @param {Object} config.constants - App constants from constants.json
 * @param {Array} config.appRoutes - Route configuration array
 * @param {string} config.defaultRoute - Initial route path
 */
createSkateboardApp({
  constants,
  appRoutes,
  defaultRoute: 'home',
  landingPage: <Navigate to="/app/home" replace />
});
