/**
 * Red-team TEST BUILD ONLY (see scripts/redteam-vscode.js). The shipped bundle never contains this:
 * the test build is made with `--alias:vscode=./test/redteam/vscode-shim.js`.
 *
 * Re-exports the real `vscode` API, but routes the dialog functions to a scripted "user"
 * (globalThis.__envSafetyRedteam, installed by test/redteam/runner.js in the same extension host), so
 * attacks can be run unattended and every message Env Safety shows can be checked.
 * Before the runner is ready, every dialog is answered "cancel" (the safe default) and recorded.
 */
// eval: keep esbuild from resolving this require through the alias (it would load this file again).
const real = eval('require')('vscode');

const DIALOGS = [
  'showWarningMessage',
  'showErrorMessage',
  'showInformationMessage',
  'showInputBox',
  'showQuickPick',
  'showOpenDialog',
  'showSaveDialog',
];

globalThis.__envSafetyRedteamEarly = globalThis.__envSafetyRedteamEarly || [];

const window = Object.create(real.window);
for (const name of DIALOGS) {
  Object.defineProperty(window, name, {
    enumerable: true,
    value: (...args) => {
      const rt = globalThis.__envSafetyRedteam;
      if (!rt) {
        globalThis.__envSafetyRedteamEarly.push({ kind: name, args, t: Date.now() });
        return Promise.resolve(undefined);
      }
      return Promise.resolve(rt.answer(name, args));
    },
  });
}

// esbuild's interop copies OWN properties only: copy every namespace, then replace `window`.
const shim = {};
for (const k of Object.getOwnPropertyNames(real)) shim[k] = real[k];
shim.window = window;
module.exports = shim;
