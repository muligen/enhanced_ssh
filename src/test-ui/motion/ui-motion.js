/**
 * SSH Workbench — Liquid selection, v3 (always-on, demand-driven).
 * GSAP Core / Timeline / Performance skills (greensock/gsap-skills).
 * This layer observes committed presentation state. It never calls an API,
 * checks a radio, changes focus, clones labels, or delays a business action.
 * Glass is an intentionally restrained CSS approximation, not Apple's renderer.
 */
(function installSshMotion() {
  'use strict';
  const gsap = window.gsap;
  const PLAYBACK_RATE = 2; // Double animation speed without changing easing or business timers.
  const root = document.querySelector('.app-shell');
  if (!gsap || !root) return;
  window.SSHMotion?.destroy();
  // This application's explicit policy is to play motion independently of the OS.
  // Reduced transparency and forced colors remain separate CSS preferences.
  const context = gsap.context(() => {});
  const groupsSelector = '.segmented-control, .operation-tabs, .workspace-tabs, .machine-list';
  const visible = (el) => Boolean(el?.isConnected && !el.closest('[hidden]') && el.getClientRects().length);
  const clamp = (min, max, value) => Math.max(min, Math.min(max, value));
  let disposed = false;
  let currentMode = 'animated';
  let activeCount = () => 0;
  let requestSync = () => {};

  const disposeMotion = (() => {
    document.documentElement.classList.add('ssh-motion-enabled', 'ssh-liquid-enabled');
    const active = new Map();
    const touched = new Set();
    const markers = new Map();
    const cleanup = [];
    const pressed = new Set();
    const pressedLenses = new Set();
    let frame = 0;
    let dead = false;
    // These groups are static in the real application. Cache their identity once;
    // the machine ROWS may be replaced, but their owning group is not.
    const groups = [...root.querySelectorAll(groupsSelector)];
    const pending = new Map(); // group -> true when geometry must snap (e.g. resize)
    const observedSizes = new WeakMap();
    const busyDot = document.querySelector('#gateway-dot');
    const busyIcon = document.querySelector('#refresh-button .ui-icon');
    let busyPending = true;
    activeCount = () => active.size;

    function listen(el, type, fn, options) {
      el?.addEventListener(type, fn, options);
      cleanup.push(() => el?.removeEventListener(type, fn, options));
    }
    function observe(el, options, fn) {
      if (!el) return;
      const observer = new MutationObserver(fn);
      observer.observe(el, options);
      cleanup.push(() => observer.disconnect());
    }
    function stop(el, clear = true) {
      active.get(el)?.kill();
      active.delete(el);
      if (clear && el?.style) {
        gsap.set(el, { clearProps: 'transform,opacity,visibility,willChange,transformOrigin' });
        touched.delete(el);
      }
    }
    function animate(el, vars, from) {
      if (!el || dead || document.hidden) return;
      stop(el, false);
      touched.add(el);
      el.style.willChange = 'transform, opacity';
      context.ignore(() => {
        const done = vars.onComplete;
        const options = { ...vars, overwrite: 'auto', onComplete() {
          active.delete(el);
          el.style.removeProperty('will-change');
          if (vars.clearProps) touched.delete(el);
          done?.();
        } };
        const tween = (from ? gsap.fromTo(el, from, options) : gsap.to(el, options)).timeScale(PLAYBACK_RATE);
        active.set(el, tween);
      });
    }
    function schedule() {
      if (!frame && !dead && !document.hidden) frame = requestAnimationFrame(flush);
    }
    function queue(group, instant = false) {
      if (!group || dead) return;
      pending.set(group, Boolean(instant || pending.get(group)));
      schedule();
    }
    function queueAll(instant = false) {
      for (const group of groups) pending.set(group, Boolean(instant || pending.get(group)));
      schedule();
    }
    function queueRelated(element) {
      // Visibility can affect descendants and controls inside the same container.
      // Relative group coordinates do not change when an unrelated panel moves.
      for (const group of groups) {
        if (group === element || element.contains(group) || group.contains(element)) queue(group);
      }
    }
    requestSync = () => queueAll(true);

    function selectedBox(group) {
      if (group.matches('.machine-list')) return group.querySelector('.machine-item.is-selected');
      return group.matches('.segmented-control')
        ? group.querySelector('input:checked + span')
        : group.querySelector('[aria-selected="true"]');
    }
    function selectionKey(group, selected) {
      if (group.matches('.machine-list')) return selected.dataset.alias;
      if (group.matches('.segmented-control')) return selected.previousElementSibling.value;
      return selected.id;
    }
    function makeMarker(group) {
      const node = document.createElement('span');
      const surface = document.createElement('span');
      const light = document.createElement('span');
      const rim = document.createElement('span');
      node.className = 'selection-marker liquid-marker';
      node.setAttribute('aria-hidden', 'true');
      surface.className = 'liquid-surface';
      light.className = 'liquid-light';
      rim.className = 'liquid-rim';
      surface.append(light, rim);
      node.append(surface);
      const kind = group.matches('.machine-list') ? 'inventory'
        : group.matches('.workspace-tabs') ? 'rail'
        : group.matches('.operation-tabs') ? 'tabs' : 'segment';
      node.dataset.motionKind = kind;
      const record = { group, node, surface, light, rim, kind, key: '', layoutKey: '', width: 0, height: 0, wasVisible: false };
      markers.set(group, record);
      return record;
    }
    function clearLens(record) {
      const { node, surface, light, rim } = record;
      stop(node, false);
      stop(surface);
      gsap.set([light, rim], { clearProps: 'transform,opacity,willChange' });
      node.style.removeProperty('will-change');
      node.classList.remove('is-travelling');
      pressedLenses.delete(record);
    }
    function finishLens(record) {
      const { node, surface, light, rim } = record;
      active.delete(node);
      gsap.set([surface, light, rim], { clearProps: 'transform,opacity,willChange' });
      node.style.removeProperty('will-change');
      node.classList.remove('is-travelling');
    }

    // Inventory markers are reattached as the same object after app.js
    // replaceChildren(), retaining their in-flight transform and visual identity.
    function measure(group) {
      const record = markers.get(group);
      if (!record) return null;
      if (!group.isConnected || group.closest('[hidden]')) {
        record.measuredWidth = record.measuredHeight = 0;
        return { record, hide: true };
      }
      const selected = selectedBox(group);
      if (!selected) return { record, hide: true };
      // Read the two rectangles once. No append(), class/style mutation or
      // visibility geometry probe is interleaved with the read phase.
      const parent = group.getBoundingClientRect();
      record.measuredWidth = parent.width;
      record.measuredHeight = parent.height;
      if (!parent.width || !parent.height) return { record, hide: true };
      const box = selected.getBoundingClientRect();
      const x = box.left - parent.left - group.clientLeft + group.scrollLeft;
      const y = box.top - parent.top - group.clientTop + group.scrollTop;
      const w = box.width, h = box.height;
      const key = selectionKey(group, selected);
      const layoutKey = [x, y, w, h].map(v => v.toFixed(2)).join(':');
      return { record, key, layoutKey, x, y, w, h, hide: !w || !h };
    }
    function syncMarker(plan, instant = false) {
      if (!plan) return;
      const { record } = plan;
      const { group, node, surface, light, rim, kind } = record;
      if (plan.hide) {
        if (record.wasVisible) clearLens(record);
        record.wasVisible = false;
        if (!node.hidden) node.hidden = true;
        if (group.classList.contains('has-motion-marker')) group.classList.remove('has-motion-marker');
        return;
      }
      const { x, y, w, h, key, layoutKey } = plan;
      if (record.wasVisible && key === record.key && layoutKey === record.layoutKey && !instant) return;
      if (node.hidden) node.hidden = false;
      if (!group.classList.contains('has-motion-marker')) group.classList.add('has-motion-marker');
      // Reappearing controls, search results, and reflow snap to correct geometry.
      // Only a genuinely different selection glides; resizing never triggers a show.
      const glide = !instant && record.wasVisible && record.key && key !== record.key && !document.hidden;
      const oldX = Number(gsap.getProperty(node, 'x')) || 0;
      const oldY = Number(gsap.getProperty(node, 'y')) || 0;
      const oldW = record.width * (Number(gsap.getProperty(node, 'scaleX')) || 1);
      const oldH = record.height * (Number(gsap.getProperty(node, 'scaleY')) || 1);
      const centerX = oldX + record.width / 2;
      const centerY = oldY + record.height / 2;
      stop(node, false);
      stop(surface, false);
      pressedLenses.delete(record);
      // Dimensions are written only at a genuine size change, never per frame.
      if (record.width !== w) node.style.width = w + 'px';
      if (record.height !== h) node.style.height = h + 'px';
      record.key = key; record.layoutKey = layoutKey;
      record.width = w; record.height = h; record.wasVisible = true;
      if (!glide) {
        clearLens(record);
        gsap.set(node, { x, y, scaleX: 1, scaleY: 1 });
        return;
      }
      const dx = x + w / 2 - centerX;
      const dy = y + h / 2 - centerY;
      const horizontal = Math.abs(dx) > Math.abs(dy);
      const distance = Math.hypot(dx, dy);
      // The larger inventory panel is quieter than the compact capsules.
      const stretch = kind === 'inventory' ? .045 : kind === 'rail' ? .12 : .17;
      const travel = kind === 'inventory' ? .48 + clamp(0, .055, distance / 6000)
        : kind === 'rail' ? .44 + clamp(0, .08, distance / 4500) : .44;
      const axis = horizontal ? 'xPercent' : 'yPercent';
      const direction = Math.sign(horizontal ? dx : dy) || 1;
      const elongate = horizontal
        ? { scaleX: 1 + stretch, scaleY: 1 - stretch * .62 }
        : { scaleX: 1 - stretch * .55, scaleY: 1 + stretch };
      const settle = horizontal ? { scaleX: .991, scaleY: 1.012 } : { scaleX: 1.007, scaleY: .991 };
      gsap.set(node, { x: centerX - w / 2, y: centerY - h / 2, scaleX: oldW / w, scaleY: oldH / h });
      gsap.set(light, { xPercent: 0, yPercent: 0, [axis]: -direction * 75, opacity: 0 });
      node.classList.add('is-travelling');
      node.style.willChange = surface.style.willChange = 'transform';
      light.style.willChange = 'transform, opacity';
      context.ignore(() => {
        const timeline = gsap.timeline({ defaults: { overwrite: 'auto' }, onComplete: () => finishLens(record) }).timeScale(PLAYBACK_RATE);
        timeline.addLabel('travel', 0)
          .to(node, { x, y, scaleX: 1, scaleY: 1, duration: travel, ease: 'power2.inOut' }, 'travel')
          .to(surface, { ...elongate, duration: travel * .28, ease: 'power2.out' }, 'travel')
          .to(surface, { ...settle, duration: travel * .60, ease: 'power2.inOut' }, travel * .28)
          .to(surface, { scaleX: 1, scaleY: 1, duration: .14, ease: 'sine.out' }, travel * .88)
          // A soft moving highlight signals material thickness, not a sparkle loop.
          .to(light, { opacity: kind === 'inventory' ? .28 : .60, duration: travel * .23, ease: 'sine.out' }, 0)
          .to(light, { [axis]: direction * 75, duration: travel, ease: 'sine.inOut' }, 0)
          .to(light, { opacity: 0, duration: travel * .47, ease: 'sine.out' }, travel * .53);
        // The rim stays static. One moving light already communicates the glass;
        // no separate rim tween or persistent compositor hint is needed.
        active.set(node, timeline);
      });
    }
    function flush() {
      frame = 0;
      if (dead || document.hidden) return;
      const work = [...pending];
      pending.clear();
      // Phase 1: create/reattach nodes. The inventory keeps the SAME lens even
      // after app.js replaceChildren(). Never measure between these appends.
      for (const [group] of work) {
        if (!group.isConnected) continue;
        let record = markers.get(group);
        if (!record && !group.closest('[hidden]') && selectedBox(group)) record = makeMarker(group);
        if (record && record.node.parentNode !== group) group.append(record.node);
      }
      // Reattach first so a replaced machine row doesn't erase an in-flight
      // marker transform. Hidden lenses are handled by syncMarker/clearLens.
      for (const el of [...active.keys()]) {
        if (!el.matches('.liquid-marker') && (!el.isConnected || el.closest('[hidden]'))) stop(el);
      }
      // Phase 2: all geometry reads. Phase 3: all styles/timelines.
      const plans = work.map(([group, instant]) => [measure(group), instant]);
      for (const [plan, instant] of plans) syncMarker(plan, instant);
      if (busyPending) {
        busyPending = false;
        const busy = busyDot?.classList.contains('is-checking');
        if (busy && busyIcon && !active.has(busyIcon)) {
          animate(busyIcon, { rotation: '+=360', repeat: -1, duration: 1, ease: 'none' });
        } else if (!busy && busyIcon && active.has(busyIcon)) stop(busyIcon);
      }
    }

    // Ignore terminal text, CSS transforms and unrelated action-button states.
    // A copy feedback or gateway status update must not remeasure every control.
    observe(root, { attributes: true, subtree: true, attributeOldValue: true, attributeFilter: ['hidden', 'aria-selected', 'data-copy-state', 'disabled'] }, (records) => {
      for (const change of records) {
        const target = change.target;
        if (change.oldValue === target.getAttribute(change.attributeName) || target.closest('.liquid-marker')) continue;
        if (change.attributeName === 'data-copy-state') {
          if (target.dataset.copyState === 'copied') {
            const check = target.querySelector('.copy-check');
            if (visible(check)) animate(check, { scale: 1, opacity: 1, duration: .18, ease: 'power2.out', clearProps: 'transform,opacity,willChange' }, { scale: .82, opacity: .6 });
          }
          continue;
        }
        if (change.attributeName === 'hidden') queueRelated(target);
        else queue(target.closest(groupsSelector));
      }
    });
    observe(document.querySelector('#machine-list'), { childList: true }, (records) => {
      if (records.some(record => [...record.addedNodes, ...record.removedNodes].some(node => !node.classList?.contains('liquid-marker')))) {
        // Choosing a machine also fills native checked properties without firing
        // change events. Reconcile all group selections for this actual UI render.
        queueAll();
      }
    });
    observe(busyDot, { attributes: true, attributeFilter: ['class'] }, () => { busyPending = true; schedule(); });
    observe(document.querySelector('#toast-region'), { childList: true }, () => {
      const toast = document.querySelector('#toast-region .toast');
      if (toast) animate(toast, { opacity: 1, y: 0, duration: .18, ease: 'power2.out', clearProps: 'transform,opacity,willChange' }, { opacity: .7, y: 4 });
    });
    listen(root, 'change', event => {
      if (event.target.matches('input[type="radio"]')) queue(event.target.closest('.segmented-control'));
    });
    listen(root, 'toggle', event => {
      const details = event.target;
      if (!details.matches('details')) return;
      const arrow = details.querySelector('.disclosure-chevron');
      if (arrow) animate(arrow, { rotation: details.open ? 180 : 0, duration: .18, ease: 'power2.out' });
      queueRelated(details);
    }, true);

    function press(event) {
      if (event.type === 'keydown' && (!['Enter', ' '].includes(event.key) || event.repeat)) return;
      if (event.type === 'pointerdown' && event.button !== 0) return;
      const control = event.target.closest('button, .segmented-control > label');
      if (!control || control.matches(':disabled') || control.querySelector('input:disabled')) return;
      const group = control.closest(groupsSelector);
      if (group && !control.matches('.machine-mcp-toggle')) {
        const record = markers.get(group);
        const selected = selectedBox(group);
        if (record && selected && (control.contains(selected) || selected.contains(control)) && !active.has(record.node)) {
          pressedLenses.add(record);
          animate(record.surface, { scaleX: .975, scaleY: .96, duration: .1, ease: 'power2.out' });
        }
        return;
      }
      if (!control.matches('button') || control.matches('.output-tab')) return;
      pressed.add(control);
      animate(control, { scale: .98, duration: .09, ease: 'power1.out' });
    }
    function release() {
      for (const control of pressed) animate(control, { scale: 1, duration: .16, ease: 'power2.out', clearProps: 'transform,willChange' });
      pressed.clear();
      for (const record of pressedLenses) if (!active.has(record.node)) animate(record.surface, { scaleX: 1, scaleY: 1, duration: .22, ease: 'power2.out', clearProps: 'transform,willChange' });
      pressedLenses.clear();
    }
    listen(root, 'pointerdown', press);
    listen(root, 'keydown', press);
    listen(window, 'pointerup', release);
    listen(window, 'pointercancel', release);
    listen(window, 'keyup', release);
    listen(window, 'blur', release);
    listen(window, 'resize', () => queueAll(true));
    if (typeof ResizeObserver === 'function') {
      const ro = new ResizeObserver(entries => {
        for (const { target, contentRect, borderBoxSize } of entries) {
          const size = `${contentRect.width}:${contentRect.height}`;
          if (observedSizes.get(target) === size) continue;
          observedSizes.set(target, size);
          const box = borderBoxSize?.[0] || borderBoxSize;
          const record = markers.get(target);
          // A visibility change is often measured in our rAF before RO delivers
          // the same size. Don't schedule a second, identical read next frame.
          // Groups have horizontal writing-mode and no transform of their own.
          if (box && record && Math.abs(record.measuredWidth - box.inlineSize) < .1
            && Math.abs(record.measuredHeight - box.blockSize) < .1) continue;
          queue(target);
        }
      });
      groups.forEach(group => ro.observe(group));
      cleanup.push(() => ro.disconnect());
    }
    if (document.fonts?.ready) document.fonts.ready.then(() => { if (!dead) queueAll(true); });
    listen(document, 'visibilitychange', () => {
      if (document.hidden) {
        if (frame) { cancelAnimationFrame(frame); frame = 0; }
        pending.clear();
        for (const record of markers.values()) clearLens(record);
        for (const el of [...active.keys()]) stop(el);
        pressed.clear();
      } else {
        busyPending = true;
        queueAll(true);
      }
    });
    queueAll(true);
    return () => {
      dead = true;
      if (frame) cancelAnimationFrame(frame);
      cleanup.forEach(fn => fn());
      for (const record of markers.values()) { clearLens(record); record.node.remove(); record.group.classList.remove('has-motion-marker'); }
      for (const el of [...touched]) stop(el);
      markers.clear(); active.clear(); pressed.clear(); pressedLenses.clear(); pending.clear();
      document.documentElement.classList.remove('ssh-motion-enabled', 'ssh-liquid-enabled');
      activeCount = () => 0; requestSync = () => {};
    };
  })();

  function closeHelp(event) {
    if (event.key !== 'Escape') return;
    const disclosure = event.target.closest?.('details[open]');
    if (disclosure) { disclosure.open = false; disclosure.querySelector('summary')?.focus(); }
  }
  document.addEventListener('keydown', closeHelp);
  window.SSHMotion = Object.freeze({
    get version() { return gsap.version; },
    get design() { return 'liquid-selection-v3'; },
    get motionPolicy() { return 'always'; },
    get mode() { return currentMode; },
    get activeAnimations() { return activeCount(); },
    refresh() { requestSync(); },
    destroy() {
      if (disposed) return;
      disposed = true; currentMode = 'destroyed'; disposeMotion(); context.revert(); document.removeEventListener('keydown', closeHelp);
    }
  });
})();
