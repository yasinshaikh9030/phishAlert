import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

// Create a container div for our React app to inject into websites
const phishAlertContainer = document.createElement('div');
phishAlertContainer.id = 'phishalert-extension-root';

// Ensure it's not overriding existing styles on body by appending to document.body
if (document.body) {
  document.body.appendChild(phishAlertContainer);
}

ReactDOM.createRoot(phishAlertContainer).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
