import { useState, type FormEvent } from 'react';
import {
  analyzeHostname,
  HOSTNAME_INPUT_TOO_LONG_EXPLANATION,
  MAX_HOSTNAME_INPUT_LENGTH,
  type DomainAnalysisResult,
  type DomainFindingKind,
  type DomainSuspicion,
} from '../detection/domain';
import './popup.css';

const suspicionPresentation: Record<
  DomainSuspicion,
  { readonly label: string; readonly explanation: string }
> = {
  none: {
    label: 'Нет выявленных признаков',
    explanation:
      'Эта ограниченная проверка не обнаружила известных сигналов. Это не подтверждает безопасность домена.',
  },
  low: {
    label: 'Низкая подозрительность',
    explanation:
      'Обнаружен слабый эвристический сигнал. Сходство само по себе не доказывает имитацию.',
  },
  medium: {
    label: 'Средняя подозрительность',
    explanation:
      'Обнаружен сильный признак сходства с эталонным доменом. Проверьте адрес и источник вручную.',
  },
  high: {
    label: 'Высокая подозрительность',
    explanation:
      'Обнаружены независимые сильные группы признаков. Это не подтверждённый фишинг; домен не блокируется автоматически.',
  },
};

const findingLabels: Record<DomainFindingKind, string> = {
  ascii_replacement: 'Замена похожих символов',
  edit_distance: 'Похоже на опечатку',
  unicode_confusable: 'Unicode-подмена символов',
  brand_in_subdomain: 'Название бренда в поддомене',
  mixed_script: 'Смешение письменностей',
};

function getResultStatusLabel(result: DomainAnalysisResult): string {
  switch (result.status) {
    case 'success':
      return 'Анализ завершён';
    case 'invalid':
      return 'Некорректный ввод';
    case 'unsupported':
      return 'Этот тип hostname не поддерживается';
  }
}

function Findings({ result }: { readonly result: DomainAnalysisResult }) {
  if (result.status === 'invalid' || result.findings.length === 0) {
    return null;
  }

  return (
    <div className="popup__findings">
      <h3 className="popup__section-title">Обнаруженные признаки</h3>
      <ul
        aria-label="Обнаруженные признаки"
        className="popup__finding-list"
        tabIndex={0}
      >
        {result.findings.map((finding) => (
          <li className="popup__finding" key={finding.id}>
            <strong>{findingLabels[finding.kind]}</strong>
            <p>{finding.explanation}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

function AnalysisResult({ result }: { readonly result: DomainAnalysisResult }) {
  const isSuccess = result.status === 'success';

  return (
    <section
      aria-live="polite"
      aria-labelledby="result-title"
      className={`popup__result popup__result--${result.status}`}
    >
      <h2 className="popup__section-title" id="result-title">
        Результат проверки
      </h2>
      <p className="popup__result-status">{getResultStatusLabel(result)}</p>

      {'normalizedHostname' in result && (
        <p className="popup__normalized">
          <span>Нормализованный hostname</span>
          <code>{result.normalizedHostname}</code>
        </p>
      )}

      {isSuccess ? (
        <>
          <div className={`popup__risk popup__risk--${result.suspicion}`}>
            <strong>{suspicionPresentation[result.suspicion].label}</strong>
            <p>{suspicionPresentation[result.suspicion].explanation}</p>
          </div>
          <Findings result={result} />
        </>
      ) : (
        <>
          <p className="popup__result-explanation">{result.explanation}</p>
          <Findings result={result} />
        </>
      )}
    </section>
  );
}

export function Popup() {
  const [hostname, setHostname] = useState('');
  const [result, setResult] = useState<DomainAnalysisResult | null>(null);

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (hostname.length > MAX_HOSTNAME_INPUT_LENGTH) {
      setResult({
        status: 'invalid',
        input: hostname,
        reasonCode: 'input_too_long',
        explanation: HOSTNAME_INPUT_TOO_LONG_EXPLANATION,
      });
      return;
    }
    setResult(analyzeHostname(hostname));
  }

  return (
    <main className="popup">
      <header className="popup__header">
        <div className="popup__mark" aria-hidden="true">
          H
        </div>
        <div>
          <h1 className="popup__title">HoneyGuard</h1>
          <p className="popup__subtitle">Ручная проверка домена</p>
        </div>
      </header>

      <p className="popup__note" id="hostname-guidance">
        Введите только hostname, не URL или email. Анализ локальный и не гарантирует безопасность;
        письма, ссылки и вкладки не проверяются.
      </p>

      <form
        aria-label="Проверка hostname"
        className="popup__form"
        onSubmit={handleSubmit}
      >
        <label className="popup__label" htmlFor="hostname">
          Доменное имя (hostname)
        </label>
        <input
          autoCapitalize="none"
          autoComplete="off"
          aria-describedby="hostname-guidance"
          className="popup__input"
          id="hostname"
          name="hostname"
          onChange={(event) => {
            setHostname(event.currentTarget.value);
            setResult(null);
          }}
          placeholder="например, rnicrosoft.com"
          spellCheck={false}
          type="text"
          value={hostname}
        />
        <button className="popup__submit" type="submit">
          Проверить
        </button>
      </form>

      {result ? (
        <AnalysisResult result={result} />
      ) : (
        <p className="popup__idle" role="status">
          Введите hostname и нажмите «Проверить». Результат появится здесь.
        </p>
      )}
    </main>
  );
}
