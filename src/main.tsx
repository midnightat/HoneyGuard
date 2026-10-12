import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Popup } from './popup/Popup';
import './styles.css';

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Не найден корневой элемент popup.');
}

createRoot(rootElement).render(
  <StrictMode>
    <Popup />
  </StrictMode>,
);
