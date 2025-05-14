// Файл: static/js/animations.js

// Ждём, пока DOM полностью загрузится
document.addEventListener('DOMContentLoaded', function () {
  // Анимируем элементы с классом "card" (карточки мероприятий)
  anime({
    targets: '.card',                // все элементы с классом "card"
    translateY: [50, 0],             // смещение снизу вверх: от 50px до 0
    opacity: [0, 1],                 // плавное увеличение прозрачности от 0 до 1
    easing: 'easeOutExpo',           // тип кривой анимации
    duration: 1000,                  // продолжительность анимации 1 секунда
    delay: anime.stagger(200)        // задержка между анимациями элементов – 200 мс
  });
});
