// Таймер для Spotizoom (вынос из index.ejs)
window.addEventListener('DOMContentLoaded', function() {
  let timer = 20;
  const timerEl = document.getElementById('timer');
  const labelEl = document.getElementById('timer-label');
  let interval = null;
  let viewedSent = false;

  if (!timerEl || !labelEl) {
    console.error('Не найден элемент timer или timer-label!');
    return;
  }

  function markViewed() {
    if (viewedSent) return;
    fetch('/viewed', { method: 'POST', headers: { 'Content-Type': 'application/json' } })
      .then(res => res.json())
      .then(data => {
        labelEl.textContent = data.success ? 'You are participating in the giveaway!' : 'View not counted, please try again';
        timerEl.style.display = 'none';
        viewedSent = true;
      })
      .catch(() => {
        labelEl.textContent = 'View not counted, please try again';
        timerEl.style.display = 'none';
      });
  }

  function startTimer() {
    if (!interval && timer > 0) {
      interval = setInterval(() => {
        if (document.visibilityState === 'visible') {
          timer--;
          timerEl.textContent = timer;
          if (timer <= 0) {
            clearInterval(interval);
            interval = null;
            markViewed();
          }
        }
      }, 1000);
      console.log('Таймер запущен');
    }
  }

  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
      startTimer();
    } else if (interval) {
      clearInterval(interval);
      interval = null;
    }
  });

  if (document.visibilityState === 'visible') {
    startTimer();
  }
});
