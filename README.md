# Awesome Agent Skills

Where agent skills are published, how to vet one before it runs, and the research behind both. 247 resources, 53 vetting tools and sources, a 20-check coverage matrix and 105 papers. Built 2026-10-26.

Browse and filter everything on the site (`docs/index.html`). Skills themselves are linked, never copied: many carry no licence, and every description is untrusted text.

## Vetting a skill before it runs

- A skill is code plus instructions. Claude Code runs a skill's load-time shell lines before the model reads it, grants its allowed-tools without asking, and keeps its frontmatter hooks running for the rest of the session. ([Claude Code skills docs (allowed-tools, hooks, ! injection, disableSkillShellExecution)](https://code.claude.com/docs/en/skills); [Anthropic Skills security considerations + Skills for enterprise](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/enterprise))
- Static scanners trade catch rate for false alarms. On 3,944 malicious and 4,000 popular benign skills, the most sensitive scanner caught 98.4% of the malicious ones but flagged 23.4% of the benign; the quietest flagged 2.1% and caught 28.7%. ([MalSkillBench: A Runtime-Verified Benchmark of Malicious Agent Skills](https://arxiv.org/abs/2606.07131))
- A skill packed so its payload only appears at run time got past every scanner tested more than 90% of the time. Running it in a sandbox and tracing what crossed the OS boundary caught 97% at a 2% false-positive rate. ([Cloak and Detonate: Scanner Evasion and Dynamic Detection of Agent Skill Malware](https://arxiv.org/abs/2607.02357))
- Cheap rules first, then an LLM judge that sees only the matched snippets, reached F1 0.82 at 1.13% false positives. ([SkillGate: Cost Efficient Runtime Malicious Skill File Detection in Coding Agents](https://arxiv.org/abs/2607.25619))
- An LLM judge alone is not a gate. Rewording a malicious skill got past LLM scanners in 36.5 to 100% of cases, and moving the payload beyond the part of the file the judge reads got past it every time. ([Under the Hood of SKILL.md: Semantic Supply-chain Attacks on AI Agent Skill Registry](https://arxiv.org/abs/2605.11418); [Content-Hiding Attacks and Defenses for LLM-Based Agent-Skill Scanners](https://doi.org/10.5281/zenodo.23505186))
- We ran four offline scanners in a sealed VM on 91 skills known to be safe (78 of ours, 13 of Anthropic's). Sentry, Cisco and SkillSpector each flagged 21 to 36% of them at HIGH or above, and at least one of the three flagged 46. Every CRITICAL, read at its line, was benign. Cisco even rated a narrowly scoped allowed-tools rule HIGH and advised granting bare Bash instead. Three more scanners added later flagged 0% (aid), 5% (ATR) and 45% (bawbel), all false alarms; bawbel rates the bare word "encode" CRITICAL. ([getsentry/skills skill-scanner](https://github.com/getsentry/skills/tree/main/skills/skill-scanner); [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner); [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector); [agent-sh/agnix](https://github.com/agent-sh/agnix); [wunderwuzzi23/aid](https://github.com/wunderwuzzi23/aid); [Agent-Threat-Rule/agent-threat-rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules); [bawbel/scanner](https://github.com/bawbel/scanner))
- One scanner's author retired it in July 2026, writing that static scanning of AI skills does not work as a security boundary. Another, ATR, sent detection reports to its maintainers' server by default until version 4.1.0. ([kurtpayne/skillscan-security](https://github.com/kurtpayne/skillscan-security); [Agent-Threat-Rule/agent-threat-rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules))
- No single tool covers the Claude Code surface. The coverage tab shows which checks are verified in code, which are only claimed, and which no tool makes.

## Where skills live

- Indexes are pointers; GitHub is the source of record. The largest indexes overlap by 70 to 80% at the repo level, and a popular skill's description appears in a median of 22 to 33 other repos.
- Stars measure a repo, not its skills: a repo with 300,000 stars can ship 15 skills.
- Several directories address AI agents directly, and skill descriptions carry trigger text such as "You MUST use this skill". The catalog stores such text as data and never acts on it.
- 12 to 24% of sampled skill repos carry no licence, so this catalog links to skills and shows only a name and a short description excerpt, never the skill text.

| SKILL.md files | count | how |
| --- | ---: | --- |
| SKILL.md files on GitHub | 6,500,000 | GitHub code search estimate, forks excluded; mostly copies vendored into projects |
| in repos that publish skills | 338,455 | majiayu000/claude-skill-registry index, 14,683 repos |
| distinct by content | 190,000 | same index, exact-fingerprint dedupe; 44% of files are copies |
| in about 55 official vendor repos | 4,200 | recursive git trees, one call per repo |

Measured 2026-10-23.

## The curated core

- We read every SKILL.md in the 50 official vendor repos, Anthropic's five marketplace repos and the 223 plugin sources claude-plugins-official pins to a commit: 7,160 files from 278 repos, 6,337 distinct skills once copies are folded. Text only, fetched 2026-10-23; nothing was installed or run. ([anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official))
- Code read each file for the features Claude Code acts on, and a sample of each flag was checked at the matched line. 380 skills in 29 repos pre-approve bare Bash in allowed-tools, 66 pipe a curl or wget download into a shell (mostly installer one-liners), 7 run shell commands at load time, 7 declare frontmatter hooks and 13 ask for a Bash call with Claude Code's sandbox switched off. None contains zero-width, bidi or Unicode Tag characters. ([Claude Code skills docs (allowed-tools, hooks, ! injection, disableSkillShellExecution)](https://code.claude.com/docs/en/skills))
- A skill installed as part of a plugin brings the rest of the plugin with it: 1,678 skills sit in plugins that also start MCP servers and 648 in plugins that bundle hooks.
- 51 descriptions tell the agent it must or should always use the skill, mostly as "Always use this skill when...".
- 1,038 of the 6,337 skills (16%) come with no licence GitHub recognises and none in their frontmatter.
- Seven offline scanners then read the whole core, in a sealed VM and on CSC's Roihu with no network. Each flagged a share at or below its rate on our known-good skills (Sentry 4.8%, Cisco 9.4%, SkillSpector 32.6%, agnix 2.7%, aid 0%, ATR 2.2%, bawbel 41% at HIGH or above), and reading a sample of every CRITICAL rule at its line found no malicious skill. What it did find: a jailbreak skill for LLM APIs in an official agent repo, an official plugin that tells the agent not to tell the user what it checked, symlinks that point outside the skill, and installers piped into a shell. ([getsentry/skills skill-scanner](https://github.com/getsentry/skills/tree/main/skills/skill-scanner); [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner); [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector); [agent-sh/agnix](https://github.com/agent-sh/agnix); [wunderwuzzi23/aid](https://github.com/wunderwuzzi23/aid); [Agent-Threat-Rule/agent-threat-rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules); [bawbel/scanner](https://github.com/bawbel/scanner))
- 13 of Spotify's 14 Confidence skills, a plugin source claude-plugins-official pins, tell the agent to send telemetry in the background (the step, the user's sentiment, errors), never to mention it, and to set it up with Claude Code's sandbox switched off. Four scanners flagged them, three through generic network or exfiltration rules; ATR's rule also names the sandbox override. None flagged the instruction to hide the telemetry from the user. ([anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official); [Agent-Threat-Rule/agent-threat-rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules); [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector); [bawbel/scanner](https://github.com/bawbel/scanner))

## Resources

### Official vendor repo (50)

| name | operator | size | stars | last activity |
| --- | --- | --- | ---: | --- |
| [openclaw/openclaw (bundled skills)](https://github.com/openclaw/openclaw) | OpenClaw | 128 SKILL.md | 392,800 | 2026-10-23 |
| [NousResearch/hermes-agent (skills)](https://github.com/NousResearch/hermes-agent) | Nous Research | 211 SKILL.md | 256,308 | 2026-10-23 |
| [anthropics/skills](https://github.com/anthropics/skills) | Anthropic | 20 SKILL.md; 5 plugins in marketplace.json | 183,104 | 2026-10-09 |
| [anthropics/claude-code (plugins dir)](https://github.com/anthropics/claude-code) | Anthropic | 10 SKILL.md | 152,938 | 2026-10-22 |
| [anthropics/claude-cookbooks (skills)](https://github.com/anthropics/claude-cookbooks) | Anthropic | 4 SKILL.md | 53,686 | 2026-10-17 |
| [github/awesome-copilot](https://github.com/github/awesome-copilot) | GitHub | 460 SKILL.md | 40,330 | 2026-10-23 |
| [vercel-labs/agent-skills](https://github.com/vercel-labs/agent-skills) | Vercel | 9 SKILL.md | 32,851 | 2026-10-14 |
| [openai/skills](https://github.com/openai/skills) | OpenAI | 44 SKILL.md (5 .system, 39 .curated) | 28,255 | 2026-09-08 |
| [google/skills](https://github.com/google/skills) | Google | 177 SKILL.md | 21,503 | 2026-10-22 |
| [huggingface/skills](https://github.com/huggingface/skills) | Hugging Face | 26 SKILL.md | 11,200 | 2026-10-21 |
| [google-labs-code/stitch-skills](https://github.com/google-labs-code/stitch-skills) | Google Labs | 16 SKILL.md | 8,542 | 2026-08-17 |
| [trailofbits/skills](https://github.com/trailofbits/skills) | Trail of Bits | 97 SKILL.md | 7,739 | 2026-10-22 |

38 more on the site.

### Plugin marketplace (24)

| name | operator | size | stars | last activity |
| --- | --- | --- | ---: | --- |
| [anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official) | Anthropic | 315 plugins (164 url, 98 git-subdir, 53 relative); 33 SKILL. | 43,951 | 2026-10-23 |
| [wshobson/agents](https://github.com/wshobson/agents) | wshobson | 94 plugins; 185 SKILL.md | 41,583 | 2026-10-19 |
| [anthropics/financial-services](https://github.com/anthropics/financial-services) | Anthropic | 19 plugins; 112 SKILL.md | 40,706 | 2026-09-21 |
| [anthropics/knowledge-work-plugins](https://github.com/anthropics/knowledge-work-plugins) | Anthropic | 123 plugins; 252 SKILL.md | 31,749 | 2026-10-22 |
| [anthropics/claude-plugins-community](https://github.com/anthropics/claude-plugins-community) | Anthropic | 2,283 plugins (1,876 url, 400 git-subdir, 7 relative) | 4,746 | 2026-10-22 |
| [davepoon/buildwithclaude](https://github.com/davepoon/buildwithclaude) | davepoon |  | 3,671 | 2026-10-20 |
| [jeremylongshore/tons-of-skills-marketplace](https://github.com/jeremylongshore/tons-of-skills-marketplace) | jeremylongshore | 6,126 SKILL.md | 2,863 | 2026-10-23 |
| [obra/superpowers-marketplace](https://github.com/obra/superpowers-marketplace) | obra | 10 plugins (url) | 1,305 | 2026-10-21 |
| [fivetaku/gptaku\_plugins](https://github.com/fivetaku/gptaku_plugins) | fivetaku |  | 1,238 | 2026-10-21 |
| [data-goblin/power-bi-agentic-development](https://github.com/data-goblin/power-bi-agentic-development) | data-goblin |  | 1,064 | 2026-10-17 |
| [numman-ali/n-skills](https://github.com/numman-ali/n-skills) | numman-ali |  | 1,051 | 2026-09-12 |
| [ananddtyagi/cc-marketplace](https://github.com/ananddtyagi/cc-marketplace) | ananddtyagi |  | 687 | 2026-01-18 |

12 more on the site.

### Registry or directory (26)

| name | operator | size | stars | last activity |
| --- | --- | --- | ---: | --- |
| [Agent Skills Hub (agentskillshub.top)](https://agentskillshub.top) | unnamed |  |  | seen 2026-10-23 |
| [agent-skills.cc](https://agent-skills.cc) | unnamed | 63,000+ |  | seen 2026-10-23 |
| [agent-skills.market](https://agent-skills.market) | unnamed |  |  | seen 2026-10-23 |
| [Agent-Skills.md](https://agent-skills.md) | unnamed |  |  | seen 2026-10-23 |
| [AgenticSkills](https://agenticskills.io) | AgenticSkills | 193 skills, 139 MCP servers, 16 categories |  | seen 2026-10-23 |
| [aitmpl.com (Claude Code Templates)](https://www.aitmpl.com) (speaks to AI agents) | davila7 | 917 SKILL.md in repo |  | seen 2026-10-23 |
| [Awesome Skills (awesomeskill.ai)](https://awesomeskill.ai) | unnamed |  |  | seen 2026-10-23 |
| [Build with Claude](https://www.buildwithclaude.com) | Dave Poon | 30,000+ plugins, 8,200+ skills, 7,500+ MCP (homepage); tiles |  | seen 2026-10-23 |
| [Claude Plugin Hub](https://claudepluginhub.com) | unnamed |  |  | seen 2026-10-23 |
| [Claude Skills Hub (claudeskills.info)](https://claudeskills.info) (speaks to AI agents) | Claude Skills Hub | 42,828+ skills; 61 categories |  | seen 2026-10-23 |
| [claude-plugins.dev](https://claude-plugins.dev) | Kamalnrf | ~9,595 plugins, 52,128 skills (third-party summary) |  | seen 2026-10-23 |
| [ClawHub](https://clawhub.ai) | OpenClaw | official feed /v1/feeds/skills ~930 KB JSON (official publis |  | seen 2026-10-23 |

14 more on the site.

### Marketplace (6)

| name | operator | size | stars | last activity |
| --- | --- | --- | ---: | --- |
| [Agensi](https://www.agensi.io) | Agensi | 1,000+ |  | seen 2026-10-23 |
| [Claude Marketplace / in-app directory](https://claude.com/marketplace) | Anthropic | 2,000+ plugins, connectors, agents, services |  | seen 2026-10-23 |
| [Codex plugin directory](https://developers.openai.com/codex/plugins) | OpenAI | over 90 curated plugins (third-party) |  | seen 2026-10-23 |
| [Gemini CLI extensions gallery](https://geminicli.com/extensions) | Google | topic gemini-cli-extension: 1,777 repos |  | seen 2026-10-23 |
| [KissMySkills / Claude Protocol (paid packs)](https://kissmyskills.com) | commercial | 1,000+ (FR page) |  | seen 2026-10-23 |
| [MCP Market skills](https://mcpmarket.com/tools/skills) | MCP Market | 364,432 skills; 20 categories |  | seen 2026-10-23 |

### Awesome list (46)

| name | operator | size | stars | last activity |
| --- | --- | --- | ---: | --- |
| [Shubhamsaboo/awesome-llm-apps](https://github.com/Shubhamsaboo/awesome-llm-apps) | Shubhamsaboo |  | 142,752 | 2026-10-22 |
| [ComposioHQ/awesome-claude-skills](https://github.com/ComposioHQ/awesome-claude-skills) | ComposioHQ | 77 link items, 37 repos; ALSO 864 SKILL.md in repo | 77,708 | 2026-09-18 |
| [hesreallyhim/awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code) | hesreallyhim | 252 link items, 240 repos | 56,285 | 2026-10-23 |
| [VoltAgent/awesome-openclaw-skills](https://github.com/VoltAgent/awesome-openclaw-skills) | VoltAgent | 837 link items (ClawHub links) | 53,273 | 2026-10-19 |
| [VoltAgent/awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills) | VoltAgent | 1,173 link items, 285 repos, 358 skill paths | 36,197 | 2026-10-22 |
| [travisvn/awesome-claude-skills](https://github.com/travisvn/awesome-claude-skills) | travisvn | 51 link items | 15,513 | 2026-04-28 |
| [BehiSecc/awesome-claude-skills](https://github.com/BehiSecc/awesome-claude-skills) | BehiSecc | 207 link items, 157 repos | 10,288 | 2026-09-21 |
| [heilcheng/awesome-agent-skills](https://github.com/heilcheng/awesome-agent-skills) | heilcheng | 362 link items, 195 repos | 6,295 | 2026-10-19 |
| [0xNyk/awesome-hermes-agent](https://github.com/0xNyk/awesome-hermes-agent) | 0xNyk |  | 5,883 | 2026-09-22 |
| [libukai/awesome-agent-skills](https://github.com/libukai/awesome-agent-skills) | libukai | 35 link items, 71 repos | 5,197 | 2026-09-04 |
| [xixu-me/awesome-persona-distill-skills](https://github.com/xixu-me/awesome-persona-distill-skills) | xixu-me |  | 4,707 | 2026-10-18 |
| [tmstack/awesome-persona-skills](https://github.com/tmstack/awesome-persona-skills) | tmstack |  | 4,310 | 2026-09-30 |

34 more on the site.

### Skill collection (44)

| name | operator | size | stars | last activity |
| --- | --- | --- | ---: | --- |
| [obra/superpowers](https://github.com/obra/superpowers) | obra | 15 SKILL.md | 303,845 | 2026-10-23 |
| [mattpocock/skills](https://github.com/mattpocock/skills) | mattpocock | 38 SKILL.md | 301,111 | 2026-10-22 |
| [affaan-m/ECC](https://github.com/affaan-m/ECC) | affaan-m | 1,062 SKILL.md | 286,675 | 2026-10-20 |
| [nextlevelbuilder/ui-ux-pro-max-skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) | nextlevelbuilder | 13 SKILL.md | 139,103 | 2026-10-23 |
| [garrytan/gstack](https://github.com/garrytan/gstack) | garrytan | 65 SKILL.md | 137,334 | 2026-10-23 |
| [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) | addyosmani | 25 SKILL.md | 109,724 | 2026-10-13 |
| [ruvnet/ruflo](https://github.com/ruvnet/ruflo) | ruvnet | 388 SKILL.md | 78,546 | 2026-10-23 |
| [K-Dense-AI/scientific-agent-skills](https://github.com/K-Dense-AI/scientific-agent-skills) | K-Dense-AI | 177 SKILL.md | 53,969 | 2026-10-19 |
| [Imbad0202/academic-research-skills](https://github.com/Imbad0202/academic-research-skills) | Imbad0202 |  | 53,511 | 2026-10-23 |
| [sickn33/agentic-awesome-skills](https://github.com/sickn33/agentic-awesome-skills) | sickn33 | 425 link items, 402 repos; 8,451 SKILL.md | 48,347 | 2026-10-23 |
| [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) | zhaoxuya520 | 89 SKILL.md | 43,063 | 2026-09-22 |
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | mukul975 |  | 34,874 | 2026-08-31 |

32 more on the site.

### Aggregator (11)

| name | operator | size | stars | last activity |
| --- | --- | --- | ---: | --- |
| [quemsah/awesome-claude-plugins](https://github.com/quemsah/awesome-claude-plugins) | quemsah | 100 link items | 1,464 | 2026-10-23 |
| [majiayu000/claude-skill-registry](https://github.com/majiayu000/claude-skill-registry) | majiayu000 | 33,576+ SKILL.md in main (tree truncated) | 688 | 2026-10-22 |
| [zhuyansen/agent-skills-hub](https://github.com/zhuyansen/agent-skills-hub) | zhuyansen |  | 463 | 2026-10-23 |
| [kael-odin/awesome-academic-research-skills](https://github.com/kael-odin/awesome-academic-research-skills) | kael-odin |  | 167 | 2026-10-22 |
| [Chat2AnyLLM/awesome-claude-skills](https://github.com/Chat2AnyLLM/awesome-claude-skills) | Chat2AnyLLM | table: 7,524 rows, sum 106,073; 1,852 repos with 0 | 152 | 2026-10-23 |
| [linny006/trending-claude-skills](https://github.com/linny006/trending-claude-skills) | linny006 | 63 link items | 132 | 2026-10-23 |
| [Chat2AnyLLM/awesome-claude-plugins](https://github.com/Chat2AnyLLM/awesome-claude-plugins) | Chat2AnyLLM | 4,210 table rows | 118 | 2026-10-23 |
| [Chat2AnyLLM/awesome-repo-configs](https://github.com/Chat2AnyLLM/awesome-repo-configs) | Chat2AnyLLM | skill\_repos.json 7,564 entries; plugin\_repos.json 1.85 MB | 7 | 2026-10-23 |
| [Claude Market (claudemarket.ai)](https://claudemarket.ai) | unnamed | 23,000+ items; 13,870+ MCP; 4,384+ skills; ~1,463 marketplac |  | seen 2026-10-23 |
| [Claude Marketplaces (claudemarketplaces.com)](https://claudemarketplaces.com) | mertbuilds.com | 23,683 skills; 12,869 MCP; 2,734 marketplaces |  | seen 2026-10-23 |
| [majiayu000 Claude Skills Registry (site)](https://majiayu000.github.io/claude-skill-registry/) | majiayu000 | stats.json read 2026-10-23 |  | seen 2026-10-23 |

### CLI (12)

| name | operator | size | stars | last activity |
| --- | --- | --- | ---: | --- |
| [npx skills (vercel-labs/skills)](https://github.com/vercel-labs/skills) | Vercel |  | 36,184 | 2026-10-19 |
| [claude-code-templates CLI](https://github.com/davila7/claude-code-templates) | davila7 |  | 32,845 | 2026-10-23 |
| [openskills](https://github.com/numman-ali/openskills) | numman-ali |  | 10,807 | 2026-01-18 |
| [clawhub CLI](https://github.com/openclaw/clawhub) | OpenClaw |  | 9,526 | 2026-10-22 |
| [agent-skills-platform](https://github.com/FrancyJGLisboa/agent-skills-platform) | FrancyJGLisboa |  | 2,408 | 2026-09-15 |
| [ai-agent-skills](https://github.com/MoizIbnYousaf/ai-agent-skills) | MoizIbnYousaf | 12+ runtimes | 1,152 | 2026-09-21 |
| [Smithery CLI](https://github.com/arcadeai-labs/smithery-cli) | Smithery (repo now under arcadeai-labs) |  | 848 | 2026-05-31 |
| [claude-plugins / skills-installer](https://github.com/Kamalnrf/claude-plugins) | Kamalnrf |  | 563 | 2026-10-19 |
| [mcp-linker](https://github.com/milisp/mcp-linker) | milisp |  | 345 | 2026-10-23 |
| [tessl CLI](https://github.com/tesslio/cli) | Tessl |  | 70 | 2026-03-05 |
| [code-agent-manager](https://github.com/Chat2AnyLLM/code-agent-manager) | Chat2AnyLLM |  | 51 | 2026-08-17 |
| [sk CLI (claude-skill-manager)](https://github.com/majiayu000/claude-skill-manager) | majiayu000 |  | 19 | 2026-10-02 |

### Spec and docs (10)

| name | operator | size | stars | last activity |
| --- | --- | --- | ---: | --- |
| [Agent Skills specification (agentskills.io)](https://github.com/agentskills/agentskills) | Agentic AI Foundation / Anthropic origin | clients.jsx: 46 names | 26,454 | 2026-08-09 |
| [ClawHub docs (api.md, clawhub.md)](https://github.com/openclaw/clawhub) | OpenClaw | 2,194 files in repo | 9,526 | 2026-10-22 |
| [Claude Code docs: plugin marketplaces](https://code.claude.com/docs/en/plugin-marketplaces) | Anthropic |  |  | seen 2026-10-23 |
| [Claude Code docs: skills](https://code.claude.com/docs/en/skills) | Anthropic |  |  | seen 2026-10-23 |
| [Claude help: browse skills, connectors, plugins](https://support.claude.com/en/articles/14328846-browse-skills-connectors-and-plugins-in-one-directory) | Anthropic |  |  | seen 2026-10-23 |
| [Claude platform docs: Agent Skills + enterprise vetting](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview) | Anthropic |  |  | seen 2026-10-23 |
| [Gemini CLI docs: extensions](https://geminicli.com/docs/extensions/) | Google |  |  | seen 2026-10-23 |
| [OpenAI Codex docs: build plugins](https://developers.openai.com/codex/plugins/build) | OpenAI |  |  | seen 2026-10-23 |
| [OpenAI Codex docs: skills](https://developers.openai.com/codex/skills) | OpenAI |  |  | seen 2026-10-23 |
| [skills.sh docs (cli, api, faq)](https://skills.sh/docs) | Vercel |  |  | seen 2026-10-23 |

### MCP registry (adjacent) (18)

| name | operator | size | stars | last activity |
| --- | --- | --- | ---: | --- |
| [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) | punkpeye |  | 96,769 | 2026-10-23 |
| [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MCP project |  | 91,495 | 2026-10-22 |
| [Official MCP Registry](https://github.com/modelcontextprotocol/registry) | MCP project |  | 7,396 | 2026-10-21 |
| [appcypher/awesome-mcp-servers](https://github.com/appcypher/awesome-mcp-servers) | appcypher |  | 5,797 | 2026-05-06 |
| [wong2/awesome-mcp-servers (mcpservers.org)](https://github.com/wong2/awesome-mcp-servers) | wong2 |  | 4,379 | 2026-07-13 |
| [Microsoft MCP catalog](https://github.com/microsoft/mcp) | Microsoft |  | 3,795 | 2026-10-23 |
| [Cline MCP Marketplace](https://github.com/cline/mcp-marketplace) | Cline |  | 795 | 2025-06-24 |
| [Docker MCP Catalog](https://github.com/docker/mcp-registry) | Docker |  | 574 | 2026-10-23 |
| [mcp-get community servers](https://github.com/mcp-get/community-servers) | mcp-get |  | 68 | 2026-06-17 |
| [ToolHive catalog](https://github.com/stacklok/toolhive-catalog) | Stacklok |  | 24 | 2026-10-23 |
| [Claude connectors directory](https://claude.com/connectors) | Anthropic |  |  | seen 2026-10-23 |
| [GitHub MCP Registry](https://github.com/mcp) | GitHub |  |  | seen 2026-10-23 |

6 more on the site.

## Skills: the curated core

6,343 distinct skills (7,160 SKILL.md files; copies are folded together) from 278 repos: the official vendor repos, Anthropic's marketplace repos, and the plugin sources that claude-plugins-official pins. Fetched 2026-10-25 from GitHub as text; nothing was installed or run. Browse and filter them in the Skills tab of the site.

Flags are facts read from each SKILL.md and its plugin by code, not verdicts.

| flag | skills | what it means |
| --- | ---: | --- |
| Load-time shell | 7 | Uses the !\`cmd\` syntax, which runs a shell command when the skill loads |
| Hooks in frontmatter | 7 | Declares hooks: commands that run on agent events while the skill is active |
| Bare Bash pre-approved | 381 | allowed-tools grants Bash with no command pattern, so any command runs without a prompt |
| Plugin bundles hooks | 651 | Its plugin ships hooks/hooks.json |
| Plugin bundles MCP | 1,681 | Its plugin ships .mcp.json, which starts MCP servers |
| Pipe to shell | 66 | SKILL.md contains a curl or wget piped into a shell |
| Sandbox switched off | 13 | SKILL.md asks for a Bash call with dangerouslyDisableSandbox set to true, which runs it outside Claude Code's sandbox |
| Pushy description | 51 | The description tells the agent it must or should always use the skill |
| Frontmatter not strict YAML | 1 | Strict parsers (and most scanners) skip this frontmatter |
| No frontmatter | 7 | SKILL.md has no YAML frontmatter |
| Name differs from folder | 418 | The frontmatter name is not the folder name, as the Agent Skills spec requires |
| In a test or example folder | 8 | Sits under tests, fixtures, examples or samples; may be deliberately bad |

| main subject (given by an LLM from name and description) | skills |
| --- | ---: |
| AI and agent engineering | 617 |
| DevOps, cloud and infrastructure | 613 |
| Databases and data engineering | 551 |
| Security | 408 |
| Data science and machine learning | 403 |
| Frontend, UI and design | 376 |
| Backend and APIs | 376 |
| Finance, trading and accounting | 333 |
| Monitoring and observability | 328 |
| Business, product and operations | 294 |
| Marketing, SEO, sales and social | 252 |
| Mobile and desktop apps | 241 |
| Science and research | 222 |
| Image, video and audio | 192 |
| Code quality, review and debugging | 169 |
| Testing and QA | 151 |
| Automation and app integrations | 108 |
| Web search, browsing and scraping | 106 |
| Writing and documentation | 103 |
| Productivity and personal knowledge | 97 |
| CLI, shell and system administration | 85 |
| Git, pull requests and releases | 83 |
| Office documents, slides and diagrams | 73 |
| Game development | 56 |
| Legal and compliance | 38 |
| Medicine and health | 37 |
| Other | 19 |

## How the skills were analysed

1. **Harvest.** Every SKILL.md in the 50 official vendor repos, Anthropic's five marketplace repos and the 223 plugin sources that claude-plugins-official pins to a commit, read from GitHub as text at that commit. Copies were folded by content hash. No skill was installed or executed at any step below. ([anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official))
2. **Structural flags.** Code read each file for the features Claude Code acts on without asking: pre-approved Bash, load-time shell, frontmatter hooks, plugin hooks and MCP servers, downloads piped into a shell, invisible characters, descriptions that push the agent to use the skill. A sample of every flag was read at the matched line, and three rules were tightened after that read. ([Claude Code skills docs (allowed-tools, hooks, ! injection, disableSkillShellExecution)](https://code.claude.com/docs/en/skills))
3. **Known-good baseline.** Seven offline scanners (Sentry, Cisco, SkillSpector, agnix, then aid, ATR and bawbel) and the Agent Skills spec validator first ran on 91 skills known to be safe, ours and Anthropic's, to measure how often each flags harmless skills. Every CRITICAL was read at its line. A fifth candidate, skillscan-security, was left out: its author had retired it. ([getsentry/skills skill-scanner](https://github.com/getsentry/skills/tree/main/skills/skill-scanner); [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner); [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector); [agent-sh/agnix](https://github.com/agent-sh/agnix); [wunderwuzzi23/aid](https://github.com/wunderwuzzi23/aid); [Agent-Threat-Rule/agent-threat-rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules); [bawbel/scanner](https://github.com/bawbel/scanner); [Agent Skills specification + skills-ref validator](https://github.com/agentskills/agentskills); [kurtpayne/skillscan-security](https://github.com/kurtpayne/skillscan-security))
4. **Scanning the core.** The same scanners then read the full folder of every harvested skill, scripts included, fetched at the pinned commit and checked against git hashes. They ran with no network, first in a disposable local VM, then as identical images on CSC's Roihu cluster; for each set of scanners, 30 skills run in both places gave identical findings. ([getsentry/skills skill-scanner](https://github.com/getsentry/skills/tree/main/skills/skill-scanner); [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner); [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector); [agent-sh/agnix](https://github.com/agent-sh/agnix); [wunderwuzzi23/aid](https://github.com/wunderwuzzi23/aid); [Agent-Threat-Rule/agent-threat-rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules); [bawbel/scanner](https://github.com/bawbel/scanner))
5. **Subjects.** Subjects come from a label set of 29 composed from the category lists of five skill directories and Anthropic's marketplaces. An LLM (Opus 5.5) gave each skill 1 to 3, main purpose first, from its name and description, given as untrusted data with no tools and a fixed schema. On a fixed 200, Opus and Haiku 5.5 chose the same main subject for 73%, and one model's main subject was among the other's for 93%; Haiku gave two subjects to nearly every skill, so Opus labelled the core. Earlier keyword rules agreed with an LLM on 56% of 200, mostly through keyword mistakes.
6. **Reading the hits.** A finding is a signal, not a verdict. A sample of every CRITICAL rule was read at the line it points to, and each rule was classed as a real finding or a false-positive pattern.
7. **Code, dependencies and plugin roots.** Eight more offline tools read each skill's code, declared dependencies, credentials left in files and malware signatures, and the plugin roots skills install with (hooks, MCP servers, settings), in the same sealed setup. On the 91 known-good skills none of them flags any at HIGH or above, except agentshield (1). ([DataDog/guarddog](https://github.com/DataDog/guarddog); [PyCQA/bandit (six rules)](https://github.com/PyCQA/bandit); [google/osv-scanner (offline database)](https://github.com/google/osv-scanner); [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks); [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav); [YARA-X + YARA-Forge core rules](https://github.com/YARAHQ/yara-forge); [affaan-m/agentshield (npm ecc-agentshield)](https://github.com/affaan-m/agentshield); [hashgraph-online/hol-guard plugin-scanner](https://github.com/hashgraph-online/hol-guard))
8. **Install and telemetry facts.** Our own code, run inside the VM, listed what each folder does on install or use: unpinned dependencies, install hooks, lines that fetch and run something, hosts named in code, analytics hosts, background senders, and whether the skill's docs mention telemetry. These are facts, not findings.
9. **Credential hits.** Every credential hit was sorted by code into buckets and shown to a person with the value masked; no value was ever printed or tried. The plausible ones were read: none was a live credential. ([gitleaks/gitleaks](https://github.com/gitleaks/gitleaks))
10. **LLM review.** An LLM (Claude Haiku 5.5) read every skill's files as untrusted data, with no tools and a fixed answer schema, and rated its risk. Only its labels are kept, never its prose. A person read every high rating and every flag of text aimed at a reviewer, at the lines the model cited; the verdict pills show what they found.
11. **Triaging the hits.** Each group of HIGH or CRITICAL hits from the code and plugin tools (one skill, one tool, one rule) was shown to an LLM at its lines with the skill's own description and sorted into cleared or not. A person then read every group it did not clear and their verdict replaces the model's. Not cleared means beyond what the description says, a coding mistake, or a real risk; none of these is a claim about the author's intent.

Results (6,340 of 6,343 skills with reports from all 7 scanners):

| scanner | skills flagged HIGH or above | on known-good skills |
| --- | ---: | ---: |
| [Sentry skill-scanner](https://github.com/getsentry/skills/tree/main/skills/skill-scanner) | 304 (4.8%) | 24% |
| [Cisco skill-scanner (behavioral)](https://github.com/cisco-ai-defense/skill-scanner) | 597 (9.4%) | 21% |
| [SkillSpector](https://github.com/NVIDIA/SkillSpector) | 2,069 (32.6%) | 36% |
| [agnix](https://github.com/agent-sh/agnix) | 125 (2.0%) | 12% |
| [aid (invisible characters)](https://github.com/wunderwuzzi23/aid) | 0 (0.0%) | 0% |
| [ATR rules (atr scan)](https://github.com/Agent-Threat-Rule/agent-threat-rules) | 139 (2.2%) | 5% |
| [bawbel scanner](https://github.com/bawbel/scanner) | 2,582 (40.7%) | 45% |

Skills by how many of the 7 scanners flag them HIGH or above: 0: 2,765, 1: 1,936, 2: 1,153, 3: 379, 4: 98, 5: 9, 6: 0, 7: 0. Any CRITICAL finding: 1,039.

The Agent Skills spec validator ([skills-ref](https://github.com/agentskills/agentskills)) fails 2,180 of 6,343 skills (34.4%): unexpected-fields 953, flow-style 841, dir-name-mismatch 411, name-chars 42, description-length 18, compatibility-length 13.

What reading the hits found:

- Real: 13 of Spotify's 14 Confidence skills tell the agent to post telemetry to Spotify's Confidence service in the background (the step, the user's sentiment, errors), never to mention it to the user, and to run the setup with Claude Code's sandbox switched off. No other skill in the core does either. Five scanners flagged them at HIGH or above: SkillSpector all 13, through generic rules such as any curl POST; ATR 10, through a rule whose matched condition is the sandbox override; bawbel 9, GuardDog 2 and Cisco 2, through generic exfiltration, environment-read and network-flow rules. None flagged the instruction to hide the telemetry from the user. ([anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official); [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector); [Agent-Threat-Rule/agent-threat-rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules); [bawbel/scanner](https://github.com/bawbel/scanner); [DataDog/guarddog](https://github.com/DataDog/guarddog); [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner))
- No skill read at its flagged lines turned out to be malicious. Each scanner's flag rate on the core was at or below its rate on known-good skills, so on their own the flags do not separate good skills from bad ones. ([getsentry/skills skill-scanner](https://github.com/getsentry/skills/tree/main/skills/skill-scanner); [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner); [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector); [agent-sh/agnix](https://github.com/agent-sh/agnix))
- Real: NousResearch's hermes-agent ships a skill whose description offers to bypass safety filters on API-served LLMs; dual-use tooling aimed at LLM providers, in an official agent repo. ([NousResearch/hermes-agent (skills)](https://github.com/NousResearch/hermes-agent))
- Real: datadog-labs' Claude Code plugin tells the agent not to tell the user which state it determined, what it checked, or what it found.
- Real: skills in the growthbook and datahub repos contain symlinks that point outside the skill folder, to code shared across the repo; a skill installed on its own gets a dangling link.
- Real: 66 skills pipe a curl or wget download into a shell, mostly installer one-liners; one pipes a documentation-page URL into bash.
- Common false alarms: a vendor SDK sending its own API key to its own service, labelled exfiltration; security references that quote attacks; documented example keys; SQL and markup examples; ordinary prose matched by generic injection patterns. bawbel's YARA rules match single words: CRITICAL for encode, HIGH for A2A inside a hex colour or a migration hash. ([bawbel/scanner](https://github.com/bawbel/scanner))
- The spec validator fails a third of the core, mostly for Claude Code keys the open spec does not define (argument-hint, user-invocable, disable-model-invocation) and for YAML list syntax its strict parser refuses but Claude Code reads. ([Agent Skills specification + skills-ref validator](https://github.com/agentskills/agentskills))
- Pitfalls met on the way: SkillSpector's batch mode reports on at most 30 skills per run without saying so, so a missing report must never be read as a clean one; on the cluster a container reaches the internet unless started with no network. ([NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector))

### What this does not claim

- This is a snapshot: skills harvested and scanned on 2026-10-25. It is not updated in place; a later rescan is published as a new dated release, and each result describes the commit we scanned, linked from each row. The author may have changed the skill since; the Since scan column says when they have.
- A clean row does not mean a skill is safe. Scanners miss what they have no rule for, a payload that only appears at run time gets past static scanning, and nothing here ran the skills.
- A flag does not mean a skill is malicious. Every scanner also flags skills known to be safe; its rate on those is shown beside each count, and that rate is not a false-positive rate for the core.
- We make no catch-rate claims: there is no planted malicious set here, only known-good skills and what reading the hits found.
- LLM labels are candidates. Where a person has not read a result, the page says so.
- Beyond description, code bug and real risk describe what a file does next to what its description says, not why the author wrote it.
- A finding that a third party could exploit is held back from the page and the data until its author has had time to fix it, for at most 30 days after we notify them.

### Corrections and removal

If a result about your skill is wrong, out of date or unfair, open an issue on the repository with the skill and what is wrong; the correction template asks for both. We read the cited lines again and update or remove the result, and note the change in the data.
To have a skill or repository left out of the catalog, open an issue saying so. For anything you would rather not raise in public, use the repository's private security advisory form.

[Report an error or ask for removal](https://github.com/thirtysix/awesome-agent-skills/issues/new?template=correction.yml) · [private report](https://github.com/thirtysix/awesome-agent-skills/security/advisories/new)

## Working with skills you did not write

A skill is instructions plus code that your agent follows and runs with your permissions. Complete trust is out of reach for code you did not write: static scanners miss payloads that only appear at run time, and most of their alarms are false. What you can reach is bounded trust: you know exactly which version you run, you have read it, it can do only what it needs, and changes cannot arrive unseen. The closer a skill comes to being your own code, the closer you are to trusting it. ([MalSkillBench: A Runtime-Verified Benchmark of Malicious Agent Skills](https://arxiv.org/abs/2606.07131); [Cloak and Detonate: Scanner Evasion and Dynamic Detection of Agent Skill Malware](https://arxiv.org/abs/2607.02357))

### 0. Found it: Decide whether it is worth a look, without running anything.

- Prefer official vendor repos and curated marketplaces. A directory listing is a pointer, not a review. ([anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official))
- Read the description as advertising addressed to your agent: phrases like 'always use this skill' are there to make it fire. ([Claude Code skills docs (allowed-tools, hooks, ! injection, disableSkillShellExecution)](https://code.claude.com/docs/en/skills))

### 1. Pinned: Know exactly which bytes you would run.

- Install from a marketplace entry pinned to a commit, or copy the folder at a known commit; record the commit and a hash of the folder. A lockfile that only triggers updates is not a pin. ([Claude Code plugin marketplace pinning and name policy](https://code.claude.com/docs/en/plugins/marketplace-reference); [vercel-labs/skills CLI lockfiles and audit display](https://github.com/vercel-labs/skills))
- Where a signing scheme exists, verify the signature before use. ([NVIDIA skill trust pipeline + OMS signing (skill.oms.sig)](https://docs.nvidia.com/skills/agent-skill-trust-pipeline))

### 2. Read and scanned: Know what it says and what it runs.

- Read SKILL.md and every script it ships. Look first at what Claude Code acts on without asking: allowed-tools, frontmatter hooks, load-time shell lines, bundled hooks.json and .mcp.json, symlinks leaving the folder, downloads piped into a shell, invisible characters. ([Anthropic Skills security considerations + Skills for enterprise](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/enterprise); [Claude Code skills docs (allowed-tools, hooks, ! injection, disableSkillShellExecution)](https://code.claude.com/docs/en/skills))
- Run offline scanners in isolation (a VM, or a container with no network) and read each high-severity hit at its line. Expect most to be false: on this catalog's known-good skills the scanners flagged 12 to 36% at HIGH or above. ([getsentry/skills skill-scanner](https://github.com/getsentry/skills/tree/main/skills/skill-scanner); [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner); [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector); [agent-sh/agnix](https://github.com/agent-sh/agnix))
- Review against a checklist, so the review covers the known attack classes and not only what the scanners look for. ([OWASP Agentic Skills Top 10 (AST01-10) checklist](https://owasp.github.io/www-project-agentic-skills-top-10/checklist.html); [Agent-Threat-Rule/agent-threat-rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules))

### 3. Least privilege: Limit what it can do if something was missed.

- Turn off load-time shell for skills (disableSkillShellExecution in Claude Code settings) unless you need it. ([Claude Code skills docs (allowed-tools, hooks, ! injection, disableSkillShellExecution)](https://code.claude.com/docs/en/skills))
- Never accept bare Bash in allowed-tools: narrow it to the skill's own scripts, or drop it for skills that only carry knowledge. ([agent-sh/agnix](https://github.com/agent-sh/agnix))
- Do not let a plugin's hooks or MCP servers come along unreviewed: installing a skill's plugin installs them too. ([Claude Code skills docs (allowed-tools, hooks, ! injection, disableSkillShellExecution)](https://code.claude.com/docs/en/skills))

### 4. Contained first run: See what it does before it runs with your full permissions.

- Run it first in a sandbox that limits files and network, on throwaway data, and watch what it touches. ([anthropic-experimental/sandbox-runtime (srt)](https://github.com/anthropic-experimental/sandbox-runtime); [nolabs-ai/nono](https://github.com/nolabs-ai/nono); [pipelab-org/pipelock](https://github.com/pipelab-org/pipelock))
- Runtime tracing sees what static reading cannot: in one study, payloads built to appear only at run time got past static scanners more than 90% of the time, while tracing in a sandbox caught 97%. ([Cloak and Detonate: Scanner Evasion and Dynamic Detection of Agent Skill Malware](https://arxiv.org/abs/2607.02357))

### 5. Owned: Make it your code.

- Keep your own copy in your own repository and update only by reviewing the diff. Re-scan on every change, and compare what the skill says it does, not only its bytes. ([trailofbits/mcp-context-protector](https://github.com/trailofbits/mcp-context-protector))
- Wait before adopting a new release, so a bad update has time to be noticed. ([Tessl registry security scores + install policies](https://docs.tessl.io/tutorials/protecting-against-insecure-skills))

## Vetting tools and sources

Each was read for what it actually checks; `verified by` says how (code, rules, docs or secondhand).

| how you can use it on a skill | count | which |
| --- | ---: | --- |
| Run it yourself, offline | 16 | [affaan-m/agentshield (npm ecc-agentshield)](https://github.com/affaan-m/agentshield), [Agent Skills specification + skills-ref validator](https://github.com/agentskills/agentskills), [agent-sh/agnix](https://github.com/agent-sh/agnix), [Agent-Threat-Rule/agent-threat-rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules), [bawbel/scanner](https://github.com/bawbel/scanner), [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner), [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav), [DataDog/guarddog](https://github.com/DataDog/guarddog), [getsentry/skills skill-scanner](https://github.com/getsentry/skills/tree/main/skills/skill-scanner), [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks), [google/osv-scanner (offline database)](https://github.com/google/osv-scanner), [hashgraph-online/hol-guard plugin-scanner](https://github.com/hashgraph-online/hol-guard), [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector), [PyCQA/bandit (six rules)](https://github.com/PyCQA/bandit), [wunderwuzzi23/aid](https://github.com/wunderwuzzi23/aid), [YARA-X + YARA-Forge core rules](https://github.com/YARAHQ/yara-forge) |
| Runs, but sends data or runs code elsewhere | 8 | [alexgreensh/repo-forensics](https://github.com/alexgreensh/repo-forensics), [Anthropic claude-security plugin](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/claude-security), [berabuddies/Semia](https://github.com/berabuddies/Semia), [mtthwmllr/skill-safety-auditor (Tessl)](https://tessl.io/registry/mtthwmllr/skill-safety-auditor), [openclaw/clawscan](https://github.com/openclaw/clawscan), [skillsllm.com Security Checker](https://skillsllm.com/security-check), [snyk/agent-scan (ex invariantlabs mcp-scan)](https://github.com/snyk/agent-scan), [Tencent/AI-Infra-Guard aig-skill-scan](https://github.com/Tencent/AI-Infra-Guard/tree/main/skill-scan) |
| Contain the skill at run time | 5 | [anthropic-experimental/sandbox-runtime (srt)](https://github.com/anthropic-experimental/sandbox-runtime), [lasso-security/claude-hooks (Prompt Injection Defender)](https://github.com/lasso-security/claude-hooks), [nolabs-ai/nono](https://github.com/nolabs-ai/nono), [pipelab-org/pipelock](https://github.com/pipelab-org/pipelock), [stacklok/toolhive](https://github.com/stacklok/toolhive) |
| Pin, sign or diff updates | 6 | [Claude Code plugin marketplace pinning and name policy](https://code.claude.com/docs/en/plugins/marketplace-reference), [Docker MCP Catalog (signed images, attestations)](https://docs.docker.com/ai/mcp-catalog-and-toolkit/catalog/), [GitHub CLI gh skill (preview)](https://man.archlinux.org/man/gh-skill-install.1.en), [NVIDIA skill trust pipeline + OMS signing (skill.oms.sig)](https://docs.nvidia.com/skills/agent-skill-trust-pipeline), [trailofbits/mcp-context-protector](https://github.com/trailofbits/mcp-context-protector), [vercel-labs/skills CLI lockfiles and audit display](https://github.com/vercel-labs/skills) |
| Review checklist or rules | 10 | [Anthropic Skills security considerations + Skills for enterprise](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/enterprise), [Claude Code skills docs (allowed-tools, hooks, ! injection, disableSkillShellExecution)](https://code.claude.com/docs/en/skills), [Five Eyes 'Careful Adoption of Agentic AI Services'](https://www.cisa.gov/), [Gemini CLI extension policy model](https://geminicli.com/docs/extensions/reference.md), [Microsoft: Securing AI agents when tools move from reading to acting](https://microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting), [OWASP Agentic Skills Top 10 (AST01-10) checklist](https://owasp.github.io/www-project-agentic-skills-top-10/checklist.html), [OWASP MCP Top 10 (beta)](https://owasp.org/www-project-mcp-top-10/), [OWASP Top 10 for Agentic Applications 2026 (ASI01-10)](https://genai.owasp.org/), [Pillar Security Rules File Backdoor](https://thehackernews.com/2025/03/new-rules-file-backdoor-attack-lets.html), [useai-pro/openclaw-skills skill-vetter](https://github.com/useai-pro/openclaw-skills/blob/main/skills/skill-vetter/SKILL.md) |
| Only for that registry's own listings | 5 | [ClawHub moderation (OpenClaw registry)](https://github.com/openclaw/clawhub), [Official MCP Registry (registry.modelcontextprotocol.io)](https://github.com/modelcontextprotocol/registry), [skills.sh partner audits (Gen ATH, Socket, Snyk)](https://vercel.com/changelog/automated-security-audits-now-available-for-skills-sh), [Smithery + Invariant MCP-Scan](https://invariantlabs.ai/blog/smithery-mcp-scan), [Tessl registry security scores + install policies](https://docs.tessl.io/tutorials/protecting-against-insecure-skills) |
| MCP servers, not skills | 1 | [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) |
| Avoid | 2 | [graygnatconsole/mcp-audit-tool (SUSPECT)](https://github.com/graygnatconsole/mcp-audit-tool), [kurtpayne/skillscan-security](https://github.com/kurtpayne/skillscan-security) |

### Adopt (8)

- [agent-sh/agnix](https://github.com/agent-sh/agnix): linter or checklist, verified by rules. Flagged on our known-good skills: 11 of 91 (12%) at HIGH, all real: frontmatter that strict YAML cannot parse. A linter, not a malware scanner; also flagged bare Bash in 31 skills, since fixed..
- [Anthropic Skills security considerations + Skills for enterprise](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/enterprise): guidance, verified by docs.
- [Claude Code plugin marketplace pinning and name policy](https://code.claude.com/docs/en/plugins/marketplace-reference): provenance and pinning, verified by docs.
- [Claude Code skills docs (allowed-tools, hooks, ! injection, disableSkillShellExecution)](https://code.claude.com/docs/en/skills): guidance, verified by docs.
- [DataDog/guarddog](https://github.com/DataDog/guarddog): scanner, verified by code. Flagged on our known-good skills: 0 of 91 (0%) at HIGH or above (threat-\* rules); capability-\* facts on 21..
- [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks): scanner, verified by code. Flagged on our known-good skills: 0 of 91 (0%)..
- [google/osv-scanner (offline database)](https://github.com/google/osv-scanner): scanner, verified by code. Flagged on our known-good skills: 0 of 91 (0%)..
- [OWASP Agentic Skills Top 10 (AST01-10) checklist](https://owasp.github.io/www-project-agentic-skills-top-10/checklist.html): standard, verified by docs.

### Adapt (8)

- [affaan-m/agentshield (npm ecc-agentshield)](https://github.com/affaan-m/agentshield): scanner, verified by code. Flagged on our known-good skills: 1 of 91 (1%) at HIGH or above (bare skills, where it reads little). On the core's 367 plugin roots: 157 (43%) at HIGH, Anthropic's own marketplace plugins 28 of 55 (51%): on plugins it does not separate. Read at the line: prompt-defense-missing rated CRITICAL is hygiene (shown LOW); secrets-\* in package-lock.json are integrity hashes (dropped); facts worth showing: MCP auto-approve in shipped settings, MCP servers with known vulnerabilities, hook behaviour..
- [Agent-Threat-Rule/agent-threat-rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules): standard, verified by code. Flagged on our known-good skills: 5 of 91 (5%) at HIGH or above. All read at the line: false positives (security skills quoting injections, a sanitising regex written as escape text)..
- [anthropic-experimental/sandbox-runtime (srt)](https://github.com/anthropic-experimental/sandbox-runtime): sandbox, verified by docs.
- [getsentry/skills skill-scanner](https://github.com/getsentry/skills/tree/main/skills/skill-scanner): scanner, verified by code. Flagged on our known-good skills: 22 of 91 (24%) at HIGH or above. Every CRITICAL read at its line: benign; one was a skill's own warning to treat pasted text as data, called prompt injection..
- [hashgraph-online/hol-guard plugin-scanner](https://github.com/hashgraph-online/hol-guard): scanner, verified by code. Flagged on our known-good skills: no plugin known-good set; on bare skills only manifest and licence notes (MEDIUM). Anthropic's own plugin roots: 14 of 55 (25%) at HIGH..
- [NVIDIA skill trust pipeline + OMS signing (skill.oms.sig)](https://docs.nvidia.com/skills/agent-skill-trust-pipeline): provenance and pinning, verified by docs.
- [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector): scanner, verified by code. Flagged on our known-good skills: 33 of 91 (36%) at HIGH or above. Its HIGH anti-refusal rule fired only on the phrase 'no warning'; credential-access HIGHs were security docs naming ~/.ssh..
- [trailofbits/mcp-context-protector](https://github.com/trailofbits/mcp-context-protector): provenance and pinning, verified by code.

### Reference (31)

- [Agent Skills specification + skills-ref validator](https://github.com/agentskills/agentskills): standard, verified by code. Flagged on our known-good skills: Fails 50 of 91 (55%): 27 flow-style lists strictyaml refuses, 17 descriptions over 1,024 characters, 6 argument-hint keys. A conformance check with no severities, not a security scan..
- [alexgreensh/repo-forensics](https://github.com/alexgreensh/repo-forensics): scanner, verified by code.
- [Anthropic claude-security plugin](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/claude-security): scanner, verified by code.
- [bawbel/scanner](https://github.com/bawbel/scanner): scanner, verified by code. Flagged on our known-good skills: 41 of 91 (45%) at HIGH or above, 12 of Anthropic's 13. All read: false positives, most from YARA rules matching single words..
- [berabuddies/Semia](https://github.com/berabuddies/Semia): scanner, verified by docs.
- [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner): scanner, verified by rules.
- [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner): scanner, verified by rules. Flagged on our known-good skills: 19 of 91 (21%) at HIGH or above; 7 of those because it misreads a scoped Bash(...) rule as no Bash and advises bare Bash. CRITICALs read: list-form subprocess calls, benign..
- [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav): scanner, verified by code. Flagged on our known-good skills: 0 of 91 (0%)..
- [ClawHub moderation (OpenClaw registry)](https://github.com/openclaw/clawhub): registry practice, verified by code.
- [Docker MCP Catalog (signed images, attestations)](https://docs.docker.com/ai/mcp-catalog-and-toolkit/catalog/): provenance and pinning, verified by docs.
- [Five Eyes 'Careful Adoption of Agentic AI Services'](https://www.cisa.gov/): guidance, verified by secondhand.
- [Gemini CLI extension policy model](https://geminicli.com/docs/extensions/reference.md): guidance, verified by docs.
- [GitHub CLI gh skill (preview)](https://man.archlinux.org/man/gh-skill-install.1.en): provenance and pinning, verified by docs.
- [lasso-security/claude-hooks (Prompt Injection Defender)](https://github.com/lasso-security/claude-hooks): sandbox, verified by docs.
- [Microsoft: Securing AI agents when tools move from reading to acting](https://microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting): guidance, verified by docs.
- [nolabs-ai/nono](https://github.com/nolabs-ai/nono): sandbox, verified by docs.
- [Official MCP Registry (registry.modelcontextprotocol.io)](https://github.com/modelcontextprotocol/registry): registry practice, verified by docs.
- [openclaw/clawscan](https://github.com/openclaw/clawscan): scanner, verified by docs.
- [OWASP MCP Top 10 (beta)](https://owasp.org/www-project-mcp-top-10/): standard, verified by docs.
- [OWASP Top 10 for Agentic Applications 2026 (ASI01-10)](https://genai.owasp.org/): standard, verified by secondhand.
- [Pillar Security Rules File Backdoor](https://thehackernews.com/2025/03/new-rules-file-backdoor-attack-lets.html): guidance, verified by secondhand.
- [pipelab-org/pipelock](https://github.com/pipelab-org/pipelock): sandbox, verified by docs.
- [PyCQA/bandit (six rules)](https://github.com/PyCQA/bandit): linter or checklist, verified by code. Flagged on our known-good skills: 0 of 91 (0%) at HIGH or above..
- [skills.sh partner audits (Gen ATH, Socket, Snyk)](https://vercel.com/changelog/automated-security-audits-now-available-for-skills-sh): registry practice, verified by docs.
- [Smithery + Invariant MCP-Scan](https://invariantlabs.ai/blog/smithery-mcp-scan): registry practice, verified by secondhand.
- [stacklok/toolhive](https://github.com/stacklok/toolhive): sandbox, verified by docs.
- [Tessl registry security scores + install policies](https://docs.tessl.io/tutorials/protecting-against-insecure-skills): registry practice, verified by docs.
- [useai-pro/openclaw-skills skill-vetter](https://github.com/useai-pro/openclaw-skills/blob/main/skills/skill-vetter/SKILL.md): linter or checklist, verified by code.
- [vercel-labs/skills CLI lockfiles and audit display](https://github.com/vercel-labs/skills): provenance and pinning, verified by code.
- [wunderwuzzi23/aid](https://github.com/wunderwuzzi23/aid): scanner, verified by code. Flagged on our known-good skills: 0 of 91 (0%) at MEDIUM or above; 9 at info, all benign: emoji variation selectors and a byte-order mark atop Microsoft .xsd files..
- [YARA-X + YARA-Forge core rules](https://github.com/YARAHQ/yara-forge): scanner, verified by code. Flagged on our known-good skills: 0 of 91 (0%)..

### Avoid (6)

- [graygnatconsole/mcp-audit-tool (SUSPECT)](https://github.com/graygnatconsole/mcp-audit-tool): scanner, verified by code.
- [kurtpayne/skillscan-security](https://github.com/kurtpayne/skillscan-security): scanner, verified by docs.
- [mtthwmllr/skill-safety-auditor (Tessl)](https://tessl.io/registry/mtthwmllr/skill-safety-auditor): linter or checklist, verified by secondhand.
- [skillsllm.com Security Checker](https://skillsllm.com/security-check): registry practice, verified by docs.
- [snyk/agent-scan (ex invariantlabs mcp-scan)](https://github.com/snyk/agent-scan): scanner, verified by docs.
- [Tencent/AI-Infra-Guard aig-skill-scan](https://github.com/Tencent/AI-Infra-Guard/tree/main/skill-scan): scanner, verified by docs.

## Coverage matrix

Which checks each tool makes. ✓ verified, ◐ partial, ○ claimed, ✕ absent, ? unknown, – not applicable.

| check | Sentry skill-scanner | Cisco skill-scanner | SkillSpector | Snyk agent-scan | aid | agentshield | ClawHub moderation | repo-forensics | ATR rules | agnix | mcp-context-protector | Cisco mcp-scanner | Claude Code plugin pins | Agent Skills validator | skills CLI lockfile | This catalog's own checks |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| frontmatter hooks (SKILL.md hooks:) | ✓ | ✕ | ✕ | ? | – | ◐ | – | ✕ | ○ | ◐ | – | – | – | ◐ | ✕ | ✕ |
| load-time shell (!\`cmd\`, \`\`\`!) | ◐ | ✕ | ✕ | ? | – | ? | – | ✕ | ? | ◐ | – | – | – | ✕ | ✕ | ✕ |
| allowed-tools breadth (bare Bash, Bash(\*)) | ◐ | ◐ | ◐ | ? | – | ○ | – | ✕ | ○ | ✓ | – | – | – | ◐ | ✕ | ✕ |
| invisible Unicode (Tag, VS, zero-width, bidi) | ◐ | ◐ | ○ | ○ | ○ | ○ | ◐ | ✓ | ✓ | ✕ | ✕ | ? | ◐ | ✕ | ◐ | ◐ |
| hidden markdown (HTML comments, \[x\]: \# (..), alt text) | ◐ | ✕ | ○ | ? | – | ○ | ✓ | ✕ | ○ | ✕ | ✕ | ? | – | ✕ | ✕ | ✕ |
| encoded blobs (base64/hex, data: URIs) | ✓ | ○ | ○ | ○ | – | ○ | ✓ | ○ | ○ | ✕ | ✕ | ? | – | ✕ | ✕ | ✕ |
| injection prose (ignore previous, you are now) | ✓ | ○ | ○ | ○ | – | ○ | ◐ | ◐ | ✓ | ✕ | ✕ | ◐ | – | ✕ | ✕ | ✓ |
| concealment (do not tell the user, silently) | ✕ | ✕ | ? | ? | – | ? | ○ | ✕ | ○ | ✕ | ✕ | ✓ | – | ✕ | ✕ | ◐ |
| persistence targets (CLAUDE.md, settings, hooks, rc files, systemd, git hooks) | ✓ | ◐ | ○ | ? | – | ? | ◐ | ✓ | ○ | ✕ | ✕ | ? | – | ✕ | ✕ | ✕ |
| credential targets (~/.ssh, ~/.aws, .env, env dumps) | ✓ | ○ | ○ | ○ | – | ○ | ✓ | ○ | ○ | ◐ | ✕ | ◐ | – | ✕ | ✕ | ✕ |
| network / exfil (curl\|sh, sockets, URL inventory) | ✓ | ◐ | ○ | ○ | – | ? | ✓ | ◐ | ○ | ✕ | ✕ | ✓ | – | ✕ | ✕ | ◐ |
| unpinned deps (npx, uvx, PEP 723, docker tags) | ○ | ○ | ✓ | ? | – | ? | ○ | ○ | ○ | ✕ | ✕ | ? | ◐ | ✕ | ✕ | ✕ |
| install hooks (npm lifecycle, setup.py) | ✓ | ✕ | ○ | ? | – | ? | ? | ○ | ? | ✕ | ✕ | ? | ✓ | ✕ | ✕ | ✕ |
| stdlib shadowing (json.py, .pth, sitecustomize, .pyc) | ✕ | ○ | ✕ | ? | – | ? | ✕ | ○ | ? | ✕ | ✕ | ? | – | ✕ | ✕ | ✕ |
| symlinks escaping the skill | ✓ | ✕ | ✕ | ? | – | ? | ✕ | ✕ | ? | ✕ | ✕ | – | ✓ | ✕ | ✕ | ◐ |
| bundled settings / hooks.json / plugin.json | ✕ | ✕ | ✓ | ? | – | ○ | – | ◐ | ○ | ✓ | ✕ | ? | – | ✕ | ✕ | ✕ |
| MCP tool poisoning (descriptions, schemas) | ✕ | ✕ | ○ | ○ | – | ○ | – | ◐ | ✓ | ✕ | ◐ | ✓ | – | – | – | ✕ |
| rug pull / update drift | ✕ | ✕ | ◐ | ? | – | ? | ◐ | ◐ | ○ | ✕ | ✓ | ? | ✓ | ✕ | ◐ | ✕ |
| typosquat / name shadowing / impersonation | ◐ | ◐ | ✕ | ? | – | ? | ◐ | ○ | ○ | ✕ | ✕ | ? | ✓ | ✕ | ✕ | ✕ |
| trigger abuse (description stuffing, must-use, always:true) | ◐ | ◐ | ○ | ? | – | ? | ◐ | ✕ | ○ | ◐ | ✕ | ? | – | ✕ | ✕ | ✕ |

## Literature

105 papers and reports; arXiv entries were checked against the arXiv API.

### Attack (26)

- [Unicode TAG-Block Concealment of Tool-Metadata Payloads in the Model Context Protocol: An Approval-View Fidelity Gap Across Three Independent Server Implementations](https://arxiv.org/abs/2607.05744) (2026)
- [Under the Hood of SKILL.md: Semantic Supply-chain Attacks on AI Agent Skill Registry](https://arxiv.org/abs/2605.11418) (2026)
- [Trust Me, Import This: Dependency Steering Attacks via Malicious Agent Skills](https://arxiv.org/abs/2605.09594) (2026)
- [Trail of Bits: The sorry state of skill distribution](https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/) (2026)
- [Supply-Chain Poisoning Attacks Against LLM Coding Agent Skill Ecosystems](https://arxiv.org/abs/2604.03081) (2026)
- [SkillTrojan: Backdoor Attacks on Skill-Based Agent Systems](https://arxiv.org/abs/2604.06811) (2026)
- [SkillJect: Effectively Automating Skill-Based Prompt Injection for Skill-Enabled Agents](https://arxiv.org/abs/2602.14211) (2026)
- [ShareLock: A Stealthy Multi-Tool Threshold Poisoning Attack Against MCP](https://arxiv.org/abs/2606.27027) (2026)
- [Pretext: Defeating Malicious Skill Detection Frameworks for AI Agents](https://arxiv.org/abs/2609.39607) (2026)
- [PhantomSkill: Malicious Code Injection in Agent Skill Ecosystems](https://arxiv.org/abs/2606.19191) (2026)
- [Package Hallucination Attacks on Coding Agents through Prompt Injection in Rule Files](https://arxiv.org/abs/2610.09264) (2026)
- [MetaCascade: End-to-End Attacks on Agent Skills via Metadata-Only Poisoning](https://arxiv.org/abs/2610.14836) (2026)
- [MCP-ITP: An Automated Framework for Implicit Tool Poisoning in MCP](https://arxiv.org/abs/2601.07395) (2026)
- [From Approval to Abuse: Privilege Escalation Attacks on Harness-Protected Coding Agents](https://arxiv.org/abs/2610.22987) (2026)
- [Exploiting LLM Agent Supply Chains via Payload-less Skills](https://arxiv.org/abs/2605.14460) (2026)
- [ElasticBack: Stealthy Conditional Backdoor in LLM-Agent Skills via Coupled Trigger-Rule Optimization](https://arxiv.org/abs/2608.09577) (2026)
- [CompoSkill: Compositional Skill Chain Attacks from Individually Scanner-Passing LLM Agent Skills](https://arxiv.org/abs/2608.16246) (2026)
- [BadSkill: Backdoor Attacks on Agent Skills via Model-in-Skill Poisoning](https://arxiv.org/abs/2604.09378) (2026)
- [A Finger on the Scale: Covert Policy Steering through Agentic Skills](https://arxiv.org/abs/2609.02564) (2026)
- [A Blind Trust, the Bloody Thrust: When Attacker-Controlled Hook Updates Steer AI Agent Harnesses towards Malicious Behaviors](https://arxiv.org/abs/2609.03884) (2026)
- [Your AI, My Shell: Demystifying Prompt Injection Attacks on Agentic AI Coding Editors](https://arxiv.org/abs/2509.22040) (2025)
- [When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation](https://arxiv.org/abs/2509.24272) (2025)
- [Red-Teaming Coding Agents from a Tool-Invocation Perspective: An Empirical Security Assessment](https://arxiv.org/abs/2509.05755) (2025)
- [Cuckoo Attack: Stealthy and Persistent Attacks Against AI-IDE](https://arxiv.org/abs/2509.15572) (2025)
- [Beyond the Protocol: Unveiling Attack Vectors in the Model Context Protocol (MCP) Ecosystem](https://arxiv.org/abs/2506.02040) (2025)
- [Agent Skills Enable a New Class of Realistic and Trivially Simple Prompt Injections](https://arxiv.org/abs/2510.26328) (2025)

### Defence (21)

- [theriac: Structural Detection and an Evasion-Robustness Evaluation for Tool Poisoning in MCP](https://doi.org/10.5281/zenodo.21990777) (2026)
- [Structured Security Auditing and Robustness Enhancement for Untrusted Agent Skills](https://arxiv.org/abs/2604.25109) (2026)
- [SkillsMetric: Mapping the Detection Boundary of Static Analysis for Malicious Agent Skills](https://arxiv.org/abs/2608.08468) (2026)
- [SkillSieve: A Hierarchical Triage Framework for Detecting Malicious AI Agent Skills](https://arxiv.org/abs/2604.06550) (2026)
- [SkillSentry: Adaptive Honey Worlds for Dynamic Safety Testing of Agent Skills](https://arxiv.org/abs/2608.03485) (2026)
- [SkillSecurer: Detecting and Patching Prompt-Injection Vulnerabilities in AI Agent Skills](https://arxiv.org/abs/2609.14079) (2026)
- [SkillScreen: High-Recall Screening of Malicious Agent Skills with Decision Models](https://arxiv.org/abs/2610.17727) (2026)
- [SkillGate: Cost Efficient Runtime Malicious Skill File Detection in Coding Agents](https://arxiv.org/abs/2607.25619) (2026)
- [SkillConsist: Detecting Inconsistencies in Agent Skills via Bidirectional Graph Alignment](https://arxiv.org/abs/2608.07639) (2026)
- [SKILLLITE: Evidence-Guided Malicious Skill Auditing with Compact LLMs](https://arxiv.org/abs/2609.36879) (2026)
- [Runtime Skill Audit: Targeted Runtime Probing for Agent Skill Security](https://arxiv.org/abs/2606.11671) (2026)
- [RouteGuard: Internal-Signal Detection of Skill Poisoning in LLM Agents](https://arxiv.org/abs/2604.22888) (2026)
- [MalSkills: Detecting Malicious Skills in the Agentic Supply Chain via Neuro-symbolic Reasoning](https://arxiv.org/abs/2603.27204) (2026)
- [Machine Learning-Based Detection of MCP Attacks](https://arxiv.org/abs/2604.10534) (2026)
- [From Component Manipulation to System Compromise: Understanding and Detecting Malicious MCP Servers](https://arxiv.org/abs/2604.01905) (2026)
- [Formal Analysis and Supply Chain Security for Agentic AI Skills](https://arxiv.org/abs/2603.00195) (2026)
- [FlowGuard: From Signals to Evidence for MCP Security Detection](https://arxiv.org/abs/2607.14754) (2026)
- [Detecting Malicious Agent Skills in the Wild using Attention](https://arxiv.org/abs/2606.23416) (2026)
- [Behavioral Integrity Verification for AI Agent Skills](https://arxiv.org/abs/2605.11770) (2026)
- [Aletheia: Permission-Minimality Testing for Coding-Agent Rules](https://arxiv.org/abs/2609.39678) (2026)
- [PhantomLint: Principled Detection of Hidden LLM Prompts in Structured Documents](https://arxiv.org/abs/2508.17884) (2025)

### Attack and defence (7)

- [TrustShiftProbe: Characterizing, Benchmarking, and Defending Staged Trust Attacks on MCP Servers](https://arxiv.org/abs/2608.23763) (2026)
- [Seeing Is Not Screening: Multimodal Hidden Instruction Attacks on Agent Skill Scanners](https://arxiv.org/abs/2606.18198) (2026)
- [Red-Teaming Auto Mode: Improving Blocking Classifiers Against Malign Coding Agents](https://arxiv.org/abs/2609.19587) (2026)
- [PyCache Trap: The Inspection-Execution Gap in Agent Skill Scanners](https://arxiv.org/abs/2610.10612) (2026)
- [Content-Hiding Attacks and Defenses for LLM-Based Agent-Skill Scanners](https://doi.org/10.5281/zenodo.23505186) (2026)
- [ColluSkill: Adversarial Cross-Skill Composition for Evading Agent Skill Scanners](https://arxiv.org/abs/2608.09732) (2026)
- [Cloak and Detonate: Scanner Evasion and Dynamic Detection of Agent Skill Malware](https://arxiv.org/abs/2607.02357) (2026)

### Measurement (31)

- [When Safe Skills Collide: Measuring Compositional Risk in Agent Skill Ecosystems](https://arxiv.org/abs/2606.00448) (2026)
- [When "Do Not" Is Not Deny: Security Rules in CLAUDE.md vs Built-In Controls](https://arxiv.org/abs/2608.23550) (2026)
- [What Keeps Agent Skills from Being Reusable? Evidence from 138K SKILL.md Files](https://arxiv.org/abs/2608.08453) (2026)
- [Technical Report: Exploring the Emerging Threats of the Agent Skill Ecosystem](https://arxiv.org/abs/2605.28588) (2026)
- [Stale Instruction Files Override the Code in Coding Agents: A One-Sentence Fix](https://arxiv.org/abs/2610.30571) (2026)
- [Snyk ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) (2026)
- [Skills Are Not Islands: Measuring Dependency and Risk in Agent Skill Supply Chains](https://arxiv.org/abs/2607.01136) (2026)
- [Skill Constellations: Tracing the Supply Chain of Agent Skills on GitHub](https://arxiv.org/abs/2610.11169) (2026)
- [Scanning the Harness: Configuration Exposures in AI Coding-Agent Supply Chains](https://arxiv.org/abs/2609.07360) (2026)
- [Scan the Skill, Govern the Action: Composing Registry Verdicts with Runtime Consequence Control](https://arxiv.org/abs/2609.12001) (2026)
- [Rethinking MCP Security: A Large-Scale Study of Runtime MCP Servers and Security Scanner Reliability](https://arxiv.org/abs/2607.11086) (2026)
- [Red Skills or Blue Skills? A Dive Into Skills Published on ClawHub](https://arxiv.org/abs/2604.13064) (2026)
- [Recall Is Not Enough: A Layered Comparison of Agent-Skill Malware Scanners](https://doi.org/10.5281/zenodo.21426702) (2026)
- [Passing the Test You Trained On: Re-evaluating Prompt-Injection Detectors for LLM Agents](https://arxiv.org/abs/2610.03448) (2026)
- [My Credentials, Please: Detecting Filesystem Capability Laundering in MCP Servers at Scale](https://arxiv.org/abs/2610.22301) (2026)
- [Latent Reuse in Agent Skills: Multi-modal Clone Detection at Ecosystem Scale](https://arxiv.org/abs/2603.22447) (2026)
- [Koi Security ClawHavoc (341 malicious skills)](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) (2026)
- [How Your Credentials Are Leaked by LLM Agent Skills: An Empirical Study](https://arxiv.org/abs/2604.03070) (2026)
- [HarmfulSkillBench: How Do Harmful Skills Weaponize Your Agents?](https://arxiv.org/abs/2604.15415) (2026)
- [GitSkills: A Dataset of Agent Skills on GitHub](https://arxiv.org/abs/2608.10906) (2026)
- [Evaluating a Layered Prompt-Injection Defence for the Model Context Protocol: A Record-Level Audit of Decision Conventions, Corpus Provenance and Reproducibility](https://arxiv.org/abs/2604.17125) (2026)
- [Do Not Mention This to the User: Detecting and Understanding Malicious Agent Skills in the Wild](https://arxiv.org/abs/2602.06547) (2026)
- [Description-Code Inconsistency in Real-world MCP Servers: Measurement, Detection, and Security Implications](https://arxiv.org/abs/2606.04769) (2026)
- [Context Matters: Repository-Aware Security Analysis of the Agent Skill Ecosystem](https://arxiv.org/abs/2603.16572) (2026)
- [ClawHub Security Signals: When VirusTotal, Static Analysis, and SkillSpector Disagree](https://arxiv.org/abs/2606.01494) (2026)
- [Beyond Maliciousness: Static and Runtime Attack-Surface Profiling of Agent Skills](https://arxiv.org/abs/2610.19264) (2026)
- [An Evaluation of Large Language Models for Detection of Malicious Python Packages](https://arxiv.org/abs/2602.16304) (2026)
- [Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale](https://arxiv.org/abs/2601.10338) (2026)
- [After the Party: Growth, Governance, and Security Scanning in the OpenClaw Agent Skill Ecosystem](https://arxiv.org/abs/2609.17274) (2026)
- [Parasites in the Toolchain: A Large-Scale Analysis of Attacks on the MCP Ecosystem](https://arxiv.org/abs/2509.06572) (2025)
- [Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers](https://arxiv.org/abs/2506.13538) (2025)

### Benchmark (19)

- [Towards a Risk Assessment of Malicious Skill Files in Coding Agents](https://arxiv.org/abs/2608.05223) (2026)
- [SkillVetBench: LLM-as-Judge for Multi-Dimensional Security Risk Evaluation in Open-Source LLM Agent Skills](https://arxiv.org/abs/2606.15899) (2026)
- [SkillSafetyBench: Evaluating Agent Safety under Skill-Facing Attack Surfaces](https://arxiv.org/abs/2605.12015) (2026)
- [SkillMutator: Benchmarking and Defending Language-and-Code Cross-modal Attacks on LLM Agent Skills](https://arxiv.org/abs/2606.14154) (2026)
- [SkillHarm: Lifecycle-Aware Skill-Based Attacks via Automated Construction](https://arxiv.org/abs/2606.02540) (2026)
- [SkillAtlas: An Attack Trace Library for Agent Skills](https://arxiv.org/abs/2609.13353) (2026)
- [Skill-Inject: Measuring Agent Vulnerability to Skill File Attacks](https://arxiv.org/abs/2602.20156) (2026)
- [PIDS-Bench: Evaluating Prompt-Injection Detectors Under Over-Defense, Obfuscation, and Distribution Shift](https://arxiv.org/abs/2609.15017) (2026)
- [MaliciousSkillBench: A Comprehensive Benchmark for Malicious Agent Skill Detection](https://arxiv.org/abs/2608.19901) (2026)
- [MalSkillBench: A Runtime-Verified Benchmark of Malicious Agent Skills](https://arxiv.org/abs/2606.07131) (2026)
- [MMSkillRisk: Can Agents Stay Safe When Multimodal Skills Become Traps?](https://arxiv.org/abs/2609.35912) (2026)
- [HarnessSecurity-Bench: Do Security Mechanisms Really Protect Coding Agent Harnesses?](https://arxiv.org/abs/2610.07639) (2026)
- [COPEX: Benchmarking LLM Robustness to Adversarial Context Across Model Context Protocol (MCP) Layers](https://arxiv.org/abs/2610.04378) (2026)
- [Benchmarking Security Risk Detection and Verification in Open Agentic Skill Ecosystems](https://arxiv.org/abs/2606.00925) (2026)
- [AgentTrap: Measuring Runtime Trust Failures in Third-Party Agent Skills](https://arxiv.org/abs/2605.13940) (2026)
- [MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers](https://arxiv.org/abs/2508.14925) (2025)
- [MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols](https://arxiv.org/abs/2508.13220) (2025)
- [MCP-SafetyBench: A Benchmark for Safety Evaluation of Large Language Models with Real-World MCP Servers](https://arxiv.org/abs/2512.15163) (2025)
- [MCP Security Bench (MSB): Benchmarking Attacks Against Model Context Protocol in LLM Agents](https://arxiv.org/abs/2510.15994) (2025)

### Survey (1)

- [CSA research note: AI Agent Skill Scanners Bypassed Across the Board](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/) (2026)

## How this list treats what it collects

- Every field is untrusted text. The site escapes all of it, and links open with no referrer.
- Resources whose pages address AI agents directly are marked *speaks to AI agents*.
- The build refuses invisible Unicode (Tag characters, zero-width, bidi controls) in curated data.
- Nothing listed here was installed or run to build it. Third-party scanners read the skills' files as text in a disposable VM or container with no network; a link is not an endorsement.

## Licence

Code: MIT ([LICENSE](LICENSE)). Catalog data, README and site: CC BY 4.0 ([LICENSE-DATA](LICENSE-DATA)). Names, descriptions and other text quoted from skills, repositories and papers remain their authors'.
