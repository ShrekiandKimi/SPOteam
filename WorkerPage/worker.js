const months = [
  'Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь',
  'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь'
];

let currentDate = new Date();
let currentMonth = currentDate.getMonth();
let currentYear = currentDate.getFullYear();
let isPresent = false;

let markedDays = [2, 3, 4];

document.addEventListener('DOMContentLoaded', function() {
  renderCalendar();
  updateShiftStatus();
  setupEventListeners();
});

function setupEventListeners() {
  const prevBtn = document.getElementById('prevMonth');
  const nextBtn = document.getElementById('nextMonth');
  const markBtn = document.getElementById('markPresentBtn');
  
  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      currentMonth--;
      if (currentMonth < 0) {
        currentMonth = 11;
        currentYear--;
      }
      renderCalendar();
    });
  }
  
  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      currentMonth++;
      if (currentMonth > 11) {
        currentMonth = 0;
        currentYear++;
      }
      renderCalendar();
    });
  }
  
  if (markBtn) {
    markBtn.addEventListener('click', markPresence);
  }
}

function updateShiftStatus() {
  const statusElement = document.getElementById('shiftStatus');
  const dotElement = document.getElementById('statusDot');
  const textElement = document.getElementById('statusText');
  
  if (!statusElement || !dotElement || !textElement) return;
  
  if (isPresent) {
    statusElement.className = 'inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400';
    dotElement.className = 'size-2 bg-green-500 rounded-full mr-2';
    textElement.textContent = 'На смене';
  } else {
    statusElement.className = 'inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
    dotElement.className = 'size-2 bg-red-500 rounded-full mr-2';
    textElement.textContent = 'Не на смене';
  }
}

function markPresence() {
  const today = currentDate.getDate();
  
  if (!markedDays.includes(today)) {
    markedDays.push(today);
    markedDays.sort((a, b) => a - b);
  }
  
  isPresent = true;
  updateShiftStatus();
  renderCalendar();
  
  alert(`✅ Вы отметили присутствие на ${today} ${months[currentMonth]} ${currentYear}`);
}

function renderCalendar() {
  const monthElement = document.getElementById('currentMonth');
  if (monthElement) {
    monthElement.textContent = `${months[currentMonth]} ${currentYear}`;
  }
  
  const calendarContainer = document.querySelector('.grid.grid-cols-7');
  if (!calendarContainer) return;
  
  const headers = [];
  const existingHeaders = calendarContainer.querySelectorAll('.bg-slate-50');
  existingHeaders.forEach(h => headers.push(h.outerHTML));
  
  calendarContainer.innerHTML = '';
  
  headers.forEach(html => {
    const temp = document.createElement('div');
    temp.innerHTML = html;
    calendarContainer.appendChild(temp.firstChild);
  });
  
  if (headers.length === 0) {
    const dayNames = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'];
    dayNames.forEach((day, index) => {
      const header = document.createElement('div');
      header.className = 'bg-slate-50 dark:bg-slate-900/50 py-3 text-center text-xs font-bold text-slate-400 uppercase tracking-wider';
      if (index === 6) header.classList.add('text-red-400');
      header.textContent = day;
      calendarContainer.appendChild(header);
    });
  }
  
  const firstDay = new Date(currentYear, currentMonth, 1).getDay();
  const daysInMonth = new Date(currentYear, currentMonth + 1, 0).getDate();
  const startOffset = firstDay === 0 ? 6 : firstDay - 1;
  
  const prevMonthDays = new Date(currentYear, currentMonth, 0).getDate();
  for (let i = startOffset - 1; i >= 0; i--) {
    const day = prevMonthDays - i;
    calendarContainer.appendChild(createDayElement(day, true));
  }
  
  const today = new Date();
  for (let day = 1; day <= daysInMonth; day++) {
    const isToday = day === today.getDate() && 
                    currentMonth === today.getMonth() && 
                    currentYear === today.getFullYear();
    const isMarked = markedDays.includes(day);
    const isFuture = day > today.getDate();
    
    calendarContainer.appendChild(createDayElement(day, false, isToday, isMarked, isFuture));
  }
  
  const totalCells = startOffset + daysInMonth;
  const remainingCells = 42 - totalCells;
  for (let day = 1; day <= remainingCells; day++) {
    calendarContainer.appendChild(createDayElement(day, true));
  }
}

function createDayElement(day, isOtherMonth, isToday = false, isMarked = false, isScheduled = false) {
  const div = document.createElement('div');
  div.className = 'min-h-[100px] p-2 flex flex-col items-center justify-start group relative';
  
  if (isOtherMonth) {
    div.classList.add('bg-white', 'dark:bg-slate-900', 'opacity-40', 'italic', 'text-slate-300');
  } else {
    div.classList.add('bg-white', 'dark:bg-slate-900');
    
    if (isToday) {
      div.classList.add('border-2', 'border-primary/20', 'bg-primary/5');
    }
    
    if (isScheduled) {
      div.classList.add('hover:bg-slate-50', 'dark:hover:bg-slate-800', 'transition-colors');
    }
  }
  
  const dayNumber = document.createElement('span');
  dayNumber.className = `text-sm font-bold ${isToday ? 'text-primary' : (isOtherMonth ? 'text-slate-400' : '')}`;
  dayNumber.textContent = day;
  div.appendChild(dayNumber);
  
  if (isMarked && !isOtherMonth) {
    const dot = document.createElement('div');
    dot.className = 'mt-2 size-2 bg-primary rounded-full';
    dot.title = 'Присутствовал';
    div.appendChild(dot);
  } else if (isScheduled && !isOtherMonth && !isToday) {
    const dot = document.createElement('div');
    dot.className = 'mt-2 size-2 border-2 border-slate-300 dark:border-slate-700 rounded-full';
    dot.title = 'Запланировано';
    div.appendChild(dot);
  }
  
  return div;
}