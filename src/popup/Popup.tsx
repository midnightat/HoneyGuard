import './popup.css';

export function Popup() {
  return (
    <main className="popup">
      <header className="popup__header">
        <div className="popup__mark" aria-hidden="true">
          H
        </div>
        <h1 className="popup__title">HoneyGuard</h1>
      </header>

      <div className="popup__status" role="status" aria-live="polite">
        <span className="popup__status-dot" aria-hidden="true" />
        <span>Расширение запущено</span>
      </div>

      <p className="popup__note">
        Проверка писем и защита пока не настроены.
      </p>
    </main>
  );
}
