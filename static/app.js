document.addEventListener('DOMContentLoaded', () => {
  const sidebarLinks = document.querySelectorAll('.sidebar .nav-link');
  const syncSidebarActiveLink = () => {
    sidebarLinks.forEach(link => {
      const linkUrl = new URL(link.href, window.location.href);
      const active = linkUrl.pathname === window.location.pathname;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
  };
  syncSidebarActiveLink();

  const modal = document.querySelector('[data-modal]');
  const openButton = document.querySelector('[data-open-modal]');
  const closeButtons = document.querySelectorAll('[data-close-modal]');
  const closeModal = () => {
    if (modal) modal.hidden = true;
    document.body.classList.remove('modal-open');
  };
  openButton?.addEventListener('click', () => {
    if (!modal) return;
    modal.hidden = false;
    document.body.classList.add('modal-open');
    modal.querySelector('input')?.focus();
  });
  closeButtons.forEach(button => button.addEventListener('click', closeModal));
  modal?.addEventListener('click', event => {
    if (event.target === modal) closeModal();
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeModal();
  });
  document.querySelectorAll('.flash-close').forEach(button => {
    button.addEventListener('click', () => button.closest('.flash')?.remove());
  });

  const photoInput = document.querySelector('[data-id-photo]');
  const scanButton = document.querySelector('[data-scan-id-photo]');
  const scanResult = document.querySelector('[data-id-photo-result]');
  scanButton?.addEventListener('click', async () => {
    const photo = photoInput?.files?.[0];
    if (!photo) {
      if (scanResult) scanResult.textContent = 'Choose an ID image before scanning.';
      return;
    }
    if (photo.size > 5 * 1024 * 1024) {
      if (scanResult) scanResult.textContent = 'Image exceeds 5 MB. Choose a smaller image.';
      photoInput.value = '';
      return;
    }

    const customerForm = modal?.querySelector('form[action*="/holders"]');
    const csrf = customerForm?.querySelector('[name="csrf_token"]')?.value;
    if (!csrf) {
      if (scanResult) scanResult.textContent = 'Could not verify this session. Refresh the page and try again.';
      return;
    }

    const formData = new FormData();
    formData.append('photo', photo);
    formData.append('csrf_token', csrf);
    scanButton.disabled = true;
    if (scanResult) scanResult.textContent = 'Scanning image securely…';
    try {
      const response = await fetch('/id-photo/scan', { method: 'POST', body: formData });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'Photo scan failed.');

      const fieldNames = {
        full_name: 'full_name',
        dob_text: 'dob_text',
        document_type: 'document_type',
        document_number: 'document_number',
        issue_date: 'issue_date',
        expiry_date: 'expiry_date',
      };
      let filled = 0;
      Object.entries(result.fields || {}).forEach(([field, value]) => {
        const input = customerForm?.elements.namedItem(fieldNames[field]);
        if (input && !input.value && value) {
          input.value = value;
          input.dispatchEvent(new Event('input', { bubbles: true }));
          filled += 1;
        }
      });
      if (scanResult) {
        scanResult.textContent = filled
          ? `${filled} suggested field${filled === 1 ? '' : 's'} filled. ${result.message} Image not retained.`
          : 'No supported labeled fields were detected. Fill the form manually; image not retained.';
      }
    } catch (error) {
      if (scanResult) scanResult.textContent = error.message || 'Photo scan failed. Fill the form manually.';
    } finally {
      scanButton.disabled = false;
      if (photoInput) photoInput.value = '';
    }
  });
});
