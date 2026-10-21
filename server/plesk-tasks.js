// Plesk's background tasks (a database dump, an npm install ...) as the panel's own task bar sees them:
// GET /smb/task/task-progress lists them with a status (not_started, running, done, error, canceled) and, for a failed one, the
// real error text. A finished task stays in the list until it is removed (POST /smb/task/task-remove).
import { UserError, sleep } from './util.js';

const TASK_PATH = '/smb/task/task-progress';
const strip = (s) => String(s ?? '').replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
const FINISHED = new Set(['done', 'error', 'canceled']);

function describe(t) {
  const stepErrors = (t.steps || []).flatMap((s) => s.errors || []);
  return {
    id: String(t.id),
    status: t.status,
    title: strip(t.progressTitleHtml || t.progressTitle),
    errors: [...(t.errors || []), ...stepErrors].map(strip).filter(Boolean),
    output: (t.output || []).map(strip).filter(Boolean),
  };
}

export class PleskTasks {
  /** @param {import('./plesk-web.js').PleskWeb} web */
  constructor(web) {
    this.web = web;
  }

  async list() {
    const { body } = await this.web.request('GET', TASK_PATH);
    return Array.isArray(body?.items) ? body.items : [];
  }

  /** The ids of the tasks there are now (take this BEFORE starting something, to tell its task from the old ones). */
  async knownIds() {
    return new Set((await this.list()).map((t) => String(t.id)));
  }

  /**
   * Waits for a task to finish: the one with this `id`, or (no id) the newest of `type` that is not in `known`.
   * @returns {Promise<{id:string,status:string,title:string,errors:string[],output:string[]}>}
   */
  async wait({ id, type, known = new Set(), timeoutMs = 3600000, progress = () => {}, label = 'Working' } = {}) {
    const started = Date.now();
    const appearedBy = started + 30000; // the panel registers a task within moments
    let seen = false;
    let last = 0;
    for (;;) {
      const items = await this.list();
      const mine = id !== undefined ? items.filter((t) => String(t.id) === String(id)) : items.filter((t) => t.type === type && !known.has(String(t.id)));
      const t = mine.sort((a, b) => Number(b.id) - Number(a.id))[0];
      if (t) {
        seen = true;
        if (FINISHED.has(t.status)) return describe(t);
      } else if (!seen && Date.now() > appearedBy) {
        throw new UserError('Plesk did not start the task. Check the result and try again.');
      } else if (seen) {
        // it was in the list a moment ago and is gone now: the panel dropped it; whatever it did is done
        return { id: String(id ?? ''), status: 'done', title: '', errors: [], output: [] };
      }
      if (Date.now() - started > timeoutMs) throw new UserError(`${label} is still running after ${Math.round(timeoutMs / 60000)} minutes. It continues on the server; check in Plesk (Tasks).`);
      if (Date.now() - last >= 10000) {
        progress(`${label}… ${Math.round((Date.now() - started) / 1000)} s`);
        last = Date.now();
      }
      await sleep(Date.now() - started < 10000 ? 700 : 2500);
    }
  }

  /** Removes finished tasks from the panel's list. */
  async forget(ids) {
    if (!ids.length) return;
    await this.web.request('POST', '/smb/task/task-remove', { json: { ids } }).catch(() => {});
  }
}
