/**
 * VoteCentral Unified Toast Notification Engine
 * Provides modern glassmorphic toasts for system feedback, OTPs, auth, and voting.
 */

(function (window, document) {
  'use strict';

  const ICONS = {
    success: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" stroke-linecap="round" stroke-linejoin="round"/>
        <polyline points="22 4 12 14.01 9 11.01" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>`,
    error: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <circle cx="12" cy="12" r="10" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="15" y1="9" x2="9" y2="15" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="9" y1="9" x2="15" y2="15" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>`,
    warning: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="12" y1="9" x2="12" y2="13" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="12" y1="17" x2="12.01" y2="17" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>`,
    info: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <circle cx="12" cy="12" r="10" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="12" y1="16" x2="12" y2="12" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="12" y1="8" x2="12.01" y2="8" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>`,
    email: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" stroke-linecap="round" stroke-linejoin="round"/>
        <polyline points="22,6 12,13 2,6" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>`,
    otp: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>`,
    vote: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <rect x="2" y="6" width="20" height="14" rx="3" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="6" y1="3" x2="18" y2="3" stroke-linecap="round" stroke-linejoin="round"/>
        <polyline points="8 13 11 16 16 10" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>`
  };

  const CLOSE_ICON = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
      <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round" stroke-linejoin="round"/>
      <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;

  let container = null;

  function getContainer() {
    if (!container || !document.body.contains(container)) {
      container = document.getElementById('vc-toast-container');
      if (!container) {
        container = document.createElement('div');
        container.id = 'vc-toast-container';
        document.body.appendChild(container);
      }
    }
    return container;
  }

  function resolveCategory(cat, msg) {
    const c = (cat || '').toLowerCase().replace(/_/g, '-');
    const m = (msg || '').toLowerCase();

    let type = 'info';
    let title = 'Notification';

    if (c.includes('success') || m.includes('successful') || m.includes('created') || m.includes('recorded')) {
      type = 'success';
      title = 'Success';
    } else if (c.includes('error') || c.includes('fail') || c.includes('danger') || m.includes('invalid') || m.includes('failed') || m.includes('expired')) {
      type = 'error';
      title = 'Error';
    } else if (c.includes('warn') || m.includes('warning') || m.includes('caution')) {
      type = 'warning';
      title = 'Notice';
    }

    if (m.includes('otp') || m.includes('verification code') || c.includes('otp')) {
      if (type === 'success') {
        title = 'OTP Sent';
      } else if (type === 'error') {
        title = 'OTP Verification Failed';
      }
    } else if (m.includes('private code')) {
      title = type === 'success' ? 'Private Code Sent' : 'Private Code Delivery Notice';
    } else if (m.includes('logged in') || m.includes('logged out') || m.includes('session')) {
      title = type === 'success' ? 'Authentication' : 'Session Alert';
    } else if (m.includes('election') || m.includes('candidate') || m.includes('whitelist')) {
      title = type === 'success' ? 'Election Updated' : 'Election Notice';
    } else if (m.includes('vote')) {
      title = type === 'success' ? 'Ballot Recorded' : 'Voting Notice';
    }

    return { type, title };
  }

  const VoteCentralToast = {
    show: function (options) {
      if (typeof options === 'string') {
        options = { message: options };
      }

      const message = options.message || '';
      if (!message) return null;

      let type = options.type || 'info';
      let title = options.title;
      const duration = options.duration !== undefined ? options.duration : 4500;

      // Normalize category/type
      if (!options.title) {
        const resolved = resolveCategory(type, message);
        type = resolved.type;
        title = resolved.title;
      }

      // Map special alias types
      let iconKey = type;
      if (type === 'email' || type === 'otp' || type === 'vote') {
        iconKey = type;
      } else if (!ICONS[iconKey]) {
        iconKey = 'info';
      }

      const toastCont = getContainer();

      const toast = document.createElement('div');
      toast.className = `vc-toast vc-toast-${type}`;

      const iconSvg = ICONS[iconKey] || ICONS.info;

      toast.innerHTML = `
        <div class="vc-toast-icon">${iconSvg}</div>
        <div class="vc-toast-content">
          ${title ? `<div class="vc-toast-title">${title}</div>` : ''}
          <div class="vc-toast-message">${message}</div>
        </div>
        <button type="button" class="vc-toast-close" aria-label="Close notification">${CLOSE_ICON}</button>
        ${duration > 0 ? `<div class="vc-toast-progress"></div>` : ''}
      `;

      // Close button handler
      const closeBtn = toast.querySelector('.vc-toast-close');
      let isClosing = false;

      function removeToast() {
        if (isClosing) return;
        isClosing = true;
        toast.classList.add('vc-toast-hiding');
        setTimeout(() => {
          if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
          }
        }, 260);
      }

      if (closeBtn) {
        closeBtn.addEventListener('click', function (e) {
          e.stopPropagation();
          removeToast();
        });
      }

      // Progress bar animation
      if (duration > 0) {
        const progressBar = toast.querySelector('.vc-toast-progress');
        if (progressBar) {
          progressBar.style.animation = `vcToastProgressBar ${duration}ms linear forwards`;
        }

        const timer = setTimeout(removeToast, duration);

        toast.addEventListener('mouseenter', () => {
          if (progressBar) progressBar.style.animationPlayState = 'paused';
          clearTimeout(timer);
        });

        toast.addEventListener('mouseleave', () => {
          if (progressBar) progressBar.style.animationPlayState = 'running';
          setTimeout(removeToast, 1500);
        });
      }

      toastCont.appendChild(toast);
      return toast;
    },

    success: function (message, title, duration) {
      return this.show({ message, title: title || 'Success', type: 'success', duration });
    },

    error: function (message, title, duration) {
      return this.show({ message, title: title || 'Error', type: 'error', duration });
    },

    warning: function (message, title, duration) {
      return this.show({ message, title: title || 'Warning', type: 'warning', duration });
    },

    info: function (message, title, duration) {
      return this.show({ message, title: title || 'Information', type: 'info', duration });
    },

    email: function (message, title, duration) {
      return this.show({ message, title: title || 'Email Sent', type: 'info', icon: 'email', duration });
    },

    initFlashedMessages: function (messages) {
      if (!Array.isArray(messages) || !messages.length) return;

      messages.forEach(([category, msg], index) => {
        if (!msg) return;
        setTimeout(() => {
          const resolved = resolveCategory(category, msg);
          VoteCentralToast.show({
            message: msg,
            title: resolved.title,
            type: resolved.type
          });
        }, index * 120);
      });
    }
  };

  // Global backward-compatible wrapper
  window.VoteCentralToast = VoteCentralToast;
  window.showToast = function (message, type = 'success', title = null, duration = 4500) {
    if (!title && typeof type === 'string') {
      const resolved = resolveCategory(type, message);
      return VoteCentralToast.show({
        message: message,
        type: resolved.type,
        title: resolved.title,
        duration: duration
      });
    }
    return VoteCentralToast.show({
      message: message,
      type: type,
      title: title,
      duration: duration
    });
  };

})(window, document);
