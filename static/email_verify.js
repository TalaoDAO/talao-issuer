'use strict';
const codeForm = document.querySelector('[data-code-form]');
const verifyLabel = codeForm.querySelector('button').textContent;
const digits = [...codeForm.querySelectorAll('.code-digit')];
function distribute(value, index) {
  const numbers = value.replace(/[^0-9]/g, '').slice(0, 6 - index);
  [...numbers].forEach((digit, offset) => { digits[index + offset].value = digit; });
  digits[Math.min(index + numbers.length, 5)].focus();
}
digits.forEach((input, index) => {
  input.addEventListener('input', () => {
    const value = input.value;
    input.value = value.replace(/[^0-9]/g, '').slice(0, 1);
    if (value.length > 1) distribute(value, index);
    else if (input.value && index < 5) digits[index + 1].focus();
  });
  input.addEventListener('paste', event => {
    event.preventDefault();
    distribute(event.clipboardData.getData('text'), index);
  });
  input.addEventListener('keydown', event => {
    if (event.key === 'Backspace' && !input.value && index > 0) digits[index - 1].focus();
    if (event.key === 'ArrowLeft' && index > 0) { event.preventDefault(); digits[index - 1].focus(); }
    if (event.key === 'ArrowRight' && index < 5) { event.preventDefault(); digits[index + 1].focus(); }
  });
  input.addEventListener('focus', () => input.select());
});
codeForm.addEventListener('submit', () => {
  const button = codeForm.querySelector('button');
  button.disabled = true;
  button.textContent = 'Verifying…';
});
window.addEventListener('pageshow', () => {
  const button = codeForm.querySelector('button');
  button.disabled = false;
  button.textContent = verifyLabel;
});
