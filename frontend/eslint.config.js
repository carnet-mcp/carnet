/** The lint floor — step 035m, and the decision is which rules are allowed to have an
 *  opinion about this codebase.
 *
 *  The argument is in `docs/plans/035m-lint.md` and the short form is: **buy only the
 *  rules that guard a class the typechecker structurally cannot see, and buy nothing
 *  else.** `tsconfig.json` already runs `strict`, `noUnusedLocals`, `noUnusedParameters`,
 *  `noFallthroughCasesInSwitch`, `isolatedModules` and `verbatimModuleSyntax` in CI, which
 *  is most of what a default eslint config sells; and `@typescript-eslint/no-explicit-any`
 *  — the rule most people install eslint for — is vacuous here, because there are zero
 *  `any`s in 27,000 lines.
 *
 *  What is left after that is small and is the whole point: the Rules of Hooks, stale
 *  dependency lists, and a suppression that has stopped suppressing.
 *
 *  **No formatter, no import sorter, and no rule with an opinion about comments.** This
 *  codebase's files carry their reasoning in prose, `vi.mock`s only the api methods a test
 *  uses, hand-rolls every table and duplicates two schedule forms on a recorded argument.
 *  A config that fights any of those is the wrong config, and one that reformatted every
 *  file would bury its own findings — which is the reason this chunk exists apart from
 *  035j at all.
 */

import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // Build output and the coverage report. `node_modules` is ignored by default.
    ignores: ["dist/**", "coverage/**"],
  },

  js.configs.recommended,

  /** `recommended`, and deliberately **not** `strict` and not `*TypeChecked`.
   *
   *  `strict` adds `no-non-null-assertion`, `unified-signatures`, `prefer-literal-enum-member`
   *  and their neighbours — house-style arguments, none of them tied to a defect this
   *  repository has had, each of them worth a mechanical diff across 39 components whose
   *  comments were written to argue the opposite.
   *
   *  The type-checked tiers were measured rather than assumed, because their headline rules
   *  (`no-floating-promises`, `no-misused-promises`) guard a real hazard — an unhandled
   *  rejection in a browser is a silent failure. The measurement and the verdict are in the
   *  plan doc.
   */
  tseslint.configs.recommended,

  {
    /** **Every extension a component could arrive in, not just the two in the tree.**
     *
     *  ESLint's own default is to lint `.js`/`.mjs`/`.cjs` and nothing else — every other
     *  extension has to be claimed by a `files` entry or it is skipped with
     *  *"File ignored because no matching configuration was supplied"* and an exit code of
     *  **zero**. A first draft of this config claimed only `{ts,tsx}`, which is exactly
     *  right for the tree as it stands and silently wrong the day somebody adds a `.jsx`:
     *  the file would be unlinted, the gate would stay green, and nothing would say so.
     *  A lint floor that a new file can fall through is not a floor.
     */
    files: ["**/*.{ts,tsx,js,jsx,mjs,cjs}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      /** **These matter for JavaScript and are inert for TypeScript, which is the point.**
       *
       *  `typescript-eslint`'s recommended config turns `no-undef` **off** for `.ts`/`.tsx`
       *  — deliberately, because `tsc` already resolves every identifier and does it
       *  better — so on today's tree this list changes nothing, and a comment claiming it
       *  guards the browser's globals would be false. It is here for the case the `files`
       *  entry above exists for: a `.js` or `.jsx` file, where `no-undef` **is** live and
       *  where `document` and `window` would otherwise be reported as undefined.
       *
       *  The four Node files are given Node's globals below rather than the whole tree
       *  getting both sets, so a browser file reaching for `process` is still a finding
       *  wherever the rule is live.
       */
      globals: globals.browser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },

    plugins: { "react-hooks": reactHooks },

    /** **Two rules from this plugin, not its `recommended`.**
     *
     *  `eslint-plugin-react-hooks` v7 is no longer the two-rule plugin the ecosystem
     *  remembers: its `recommended` now ships sixteen rules derived from the React
     *  Compiler's static analysis — `purity`, `immutability`, `set-state-in-effect`,
     *  `static-components` and the rest. Those are a different decision with a different
     *  price, and taking them by accident because they arrived inside a preset with a
     *  familiar name is exactly the failure this config is written to avoid. What they
     *  say about this tree is measured and recorded in the plan doc; adopting them is a
     *  chunk of its own.
     *
     *  `rules-of-hooks` is the one rule here guarding a class nothing else in this
     *  repository's gate can see. Every page in `features/` is `useResource` → early-return
     *  `Spinner` / `Failure` / `Empty` → table, so **an early return above a hook is the
     *  normal shape of these files** and a hook added to one later lands under one by
     *  default. To the typechecker that is a plain function call; at runtime it is a
     *  corrupted state slot on the second render.
     *
     *  `exhaustive-deps` is `error` rather than the preset's `warn`, because a warning in a
     *  gate that fails on errors is a finding nobody has to act on. See the directive note
     *  below — this rule and `reportUnusedDisableDirectives` are one decision, not two.
     */
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error",

      /** **One option, and it makes this rule agree with the typechecker beside it.**
       *
       *  `tsconfig.json` has run `noUnusedLocals` in CI since the frontend job existed,
       *  and TypeScript deliberately exempts a **rest sibling** — `const { detail: _drop,
       *  ...extra } = body` in `lib/api.ts` is the language's idiom for *drop this key and
       *  keep the others*, and the discarded binding is the whole point of writing it.
       *
       *  This rule's default reports it, which was the **only** finding across 27,047
       *  lines on the first run. A rule disagreeing with the gate that already ships is a
       *  config to correct, not a line of deliberate code to rewrite — the alternative
       *  spellings are a `delete` on a copy or a hand-written pick, both worse and both a
       *  behaviour change in a chunk that is not allowed one.
       */
      "@typescript-eslint/no-unused-vars": ["error", { ignoreRestSiblings: true }],
    },

    /** **The same decision as `exhaustive-deps` above, seen from the other side.**
     *
     *  `src/lib/useResource.ts` has carried an `eslint-disable-next-line
     *  react-hooks/exhaustive-deps` since long before there was a linter to read it — the
     *  effect there takes the *caller's* deps array and is deliberately wrong by the rule's
     *  standards, for reasons its docstring argues at length. So there are only two
     *  coherent configurations: both of these on, or both off.
     *
     *  Both on is chosen. It makes that suppression true rather than decorative, and it is
     *  what stops it going quietly stale: rewrite that effect so its dependencies are
     *  honest and the suppression becomes an error instead of silently hiding the next
     *  finding.
     */
    linterOptions: { reportUnusedDisableDirectives: "error" },
  },

  {
    // The three config files and the test setup run in Node, not in a browser. This config
    // is in the list because it lints itself — `eslint .` reads it like any other file, and
    // it is the one `.js` in the tree, which is to say the one file where `no-undef` is
    // live today.
    files: ["eslint.config.js", "vite.config.ts", "vitest.config.ts", "src/test/setup.ts"],
    languageOptions: { globals: globals.node },
  },
);
