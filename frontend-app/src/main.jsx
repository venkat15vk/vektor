import { StrictMode } from 'react'
import { inject();
createRoot } from 'react-dom/client'
import './index.css'
import { inject } from "@vercel/analytics";
import App from './App.jsx'

inject();
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
