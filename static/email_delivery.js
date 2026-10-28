'use strict';
document.querySelectorAll('[data-email-delivery]').forEach(root => {
  const tabs = [...root.querySelectorAll('[data-delivery-tab]')];
  function activate(tab) {
    tabs.forEach(item => {
      const selected = item === tab;
      item.setAttribute('aria-selected', String(selected));
      item.tabIndex = selected ? 0 : -1;
      document.getElementById(item.dataset.deliveryTab).hidden = !selected;
    });
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => activate(tab));
    tab.addEventListener('keydown', event => {
      if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === 'Home' ? tabs[0] : event.key === 'End' ? tabs.at(-1) : tabs[(index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
      activate(next); next.focus();
    });
  });
  root.querySelector('[data-copy-offer]').addEventListener('click', async () => {
    const field = root.querySelector('[data-offer-value]');
    const message = root.querySelector('[data-copy-message]');
    try {
      await navigator.clipboard.writeText(field.value);
      message.textContent = 'Offer copied. Paste it into your wallet.';
    } catch (_) {
      field.hidden = false; field.readOnly = true; field.focus(); field.select();
      message.textContent = 'Select and copy this offer, then paste it into your wallet.';
    }
  });
  const form = root.querySelector('[data-delivery-form]');
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    const button = form.querySelector('button[type=submit]');
    const message = root.querySelector('[data-delivery-message]');
    button.disabled = true;
    message.textContent = 'Sending the offer to your wallet…';
    try {
      const response = await fetch(form.action, { method: 'POST', body: new FormData(form), credentials: 'same-origin' });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || 'The offer could not be sent. Please try again.');
      message.textContent = result.message;
      button.textContent = 'Offer sent';
      form.querySelector('[name=wallet_address]').readOnly = true;
    } catch (error) {
      message.textContent = error.message || 'The offer could not be sent. Please try again.';
      button.disabled = false;
    }
  });
});
