// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as domainDetection from '../detection/domain';
import { Popup } from './Popup';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function submitHostname(hostname: string) {
  fireEvent.change(screen.getByRole('textbox', { name: 'Доменное имя (hostname)' }), {
    target: { value: hostname },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Проверить' }));
}

describe('Popup', () => {
  it('shows an idle prompt without implying that protection is active', () => {
    render(<Popup />);

    expect(screen.getByRole('heading', { name: 'HoneyGuard' })).toBeTruthy();
    expect(screen.getByRole('textbox', { name: 'Доменное имя (hostname)' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Проверить' })).toBeTruthy();
    expect(screen.getByRole('status').textContent).toContain('Введите hostname');
    expect(screen.queryByRole('heading', { name: 'Результат проверки' })).toBeNull();
  });

  it.each([
    ['microsoft.com', 'Нет выявленных признаков'],
    ['xn--cntent-wqf.com', 'Низкая подозрительность'],
    ['rnicrosoft.com', 'Средняя подозрительность'],
    ['paypal.paypa1.test', 'Высокая подозрительность'],
  ])('renders the engine suspicion level for %s', (hostname, label) => {
    render(<Popup />);
    submitHostname(hostname);

    expect(screen.getByText(label)).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Результат проверки' })).toBeTruthy();
  });

  it('shows a finding and its explanation for a lookalike hostname', () => {
    render(<Popup />);
    submitHostname('rnicrosoft.com');

    expect(screen.getByText('Замена похожих символов')).toBeTruthy();
    expect(screen.getByText(/визуально заменяет часть «microsoft»/u)).toBeTruthy();
    expect(screen.getByText('rnicrosoft.com')).toBeTruthy();
  });

  it('shows the normalized hostname for Unicode and Punycode input', () => {
    render(<Popup />);
    submitHostname('bücher.de');

    expect(screen.getByText('xn--bcher-kva.de')).toBeTruthy();

    submitHostname('xn--bcher-kva.de');
    expect(screen.getAllByText('xn--bcher-kva.de')).toHaveLength(1);
  });

  it.each([
    ['', 'Hostname не может быть пустым.'],
    ['https://microsoft.com', 'Ожидался только hostname, не URL, email, порт или credentials.'],
    ['user@microsoft.com', 'Ожидался только hostname, не URL, email, порт или credentials.'],
    ['microsoft.com:443', 'Ожидался только hostname, не URL, email, порт или credentials.'],
  ])('shows invalid without a risk level for %s', (hostname, explanation) => {
    render(<Popup />);
    submitHostname(hostname);

    expect(screen.getByText('Некорректный ввод')).toBeTruthy();
    expect(screen.getByText(explanation)).toBeTruthy();
    expect(screen.queryByText(/подозрительность/iu)).toBeNull();
  });

  it('shows unsupported analysis without a risk level for an IP address', () => {
    render(<Popup />);
    submitHostname('127.0.0.1');

    expect(screen.getByText('Этот тип hostname не поддерживается')).toBeTruthy();
    expect(screen.getByText('127.0.0.1')).toBeTruthy();
    expect(screen.queryByText(/подозрительность/iu)).toBeNull();
  });

  it('preserves partial findings for unsupported hostnames without a risk level', () => {
    render(<Popup />);
    submitHostname('rnicrosoft.unknownxyz');

    expect(screen.getByText('Этот тип hostname не поддерживается')).toBeTruthy();
    expect(screen.getByText('Замена похожих символов')).toBeTruthy();
    expect(screen.queryByText(/подозрительность/iu)).toBeNull();
  });

  it.each([
    ['ASCII', 'a'.repeat(1025)],
    ['Unicode', 'ü'.repeat(1025)],
  ])('shows the pre-normalization length error for overlong %s input', (_, hostname) => {
    const analyzeHostname = vi.spyOn(domainDetection, 'analyzeHostname');
    render(<Popup />);
    submitHostname(hostname);

    expect(screen.getByText('Некорректный ввод')).toBeTruthy();
    expect(
      screen.getByText(
        'Ввод слишком длинный: допустимо не более 1024 кодовых единиц UTF-16 до IDNA-нормализации.',
      ),
    ).toBeTruthy();
    expect(screen.queryByText(/подозрительность/iu)).toBeNull();
    expect(analyzeHostname).not.toHaveBeenCalled();
    expect(
      (screen.getByRole('textbox', { name: 'Доменное имя (hostname)' }) as HTMLInputElement)
        .value,
    ).toBe(hostname);
  });

  it('does not reject input at the preliminary length limit', () => {
    render(<Popup />);
    submitHostname('a'.repeat(1024));

    expect(screen.getByText('Некорректный ввод')).toBeTruthy();
    expect(screen.getByText('Строка не является допустимым hostname.')).toBeTruthy();
    expect(screen.queryByText(/Ввод слишком длинный/u)).toBeNull();
    expect(screen.queryByText(/подозрительность/iu)).toBeNull();
  });

  it('submits through the native form submit event', () => {
    render(<Popup />);
    fireEvent.change(screen.getByRole('textbox', { name: 'Доменное имя (hostname)' }), {
      target: { value: 'microsoft.com' },
    });
    fireEvent.submit(screen.getByRole('form', { name: 'Проверка hostname' }));

    expect(screen.getByText('Нет выявленных признаков')).toBeTruthy();
  });

  it('clears a stale result when the hostname is edited', () => {
    render(<Popup />);
    submitHostname('microsoft.com');

    fireEvent.change(screen.getByRole('textbox', { name: 'Доменное имя (hostname)' }), {
      target: { value: 'paypal.com' },
    });

    expect(screen.queryByRole('heading', { name: 'Результат проверки' })).toBeNull();
    expect(screen.getByRole('status').textContent).toContain('Введите hostname');
  });

  it('keeps form controls outside the findings scrolling container', () => {
    render(<Popup />);
    submitHostname('paypal.paypa1.test');

    const form = screen.getByRole('form', { name: 'Проверка hostname' });
    const findings = screen.getByRole('list', { name: 'Обнаруженные признаки' });

    expect(form.contains(findings)).toBe(false);
    expect(findings.tabIndex).toBe(0);
    expect(screen.getByRole('button', { name: 'Проверить' })).toBeTruthy();
  });
});
