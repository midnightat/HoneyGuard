import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Popup } from './Popup';

describe('Popup', () => {
  it('shows the product name and a non-protection startup status', () => {
    const markup = renderToStaticMarkup(<Popup />);

    expect(markup).toContain('<h1 class="popup__title">HoneyGuard</h1>');
    expect(markup).toContain('role="status"');
    expect(markup).toContain('Расширение запущено');
    expect(markup).toContain('Проверка писем и защита пока не настроены.');
  });
});
