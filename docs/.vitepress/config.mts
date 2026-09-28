import { defineConfig } from 'vitepress'
import { prepareDiagrams } from '../scripts/prepare-diagrams.mjs'
import { replaceProjectPlaceholders } from '../scripts/project-metadata.mjs'
import {
  extensionVersion,
  gitCommit,
  gitCommitFull,
  githubRepo,
  isPreviewDeploy,
  projectMetadata,
  quarkusVersion,
  siteHost
} from './site'

// Run for dev and build, including direct VitePress CLI usage in Cloudflare Builds.
const diagramRevision = prepareDiagrams()

const searchZh = {
  translations: {
    button: {
      buttonText: '搜索',
      buttonAriaLabel: '搜索文档'
    },
    modal: {
      displayDetails: '显示详细列表',
      resetButtonTitle: '重置搜索',
      backButtonTitle: '关闭搜索',
      noResultsText: '没有结果',
      footer: {
        selectText: '选择',
        selectKeyAriaLabel: '回车',
        navigateText: '导航',
        navigateUpKeyAriaLabel: '上箭头',
        navigateDownKeyAriaLabel: '下箭头',
        closeText: '关闭',
        closeKeyAriaLabel: 'esc'
      }
    }
  }
}

export default defineConfig({
  title: 'Quarkus Authorization Server',
  titleTemplate: ':title · Quarkus Authorization Server',
  description: 'OAuth 2.0 and optional OpenID Connect authorization for Quarkus applications.',
  lang: 'en-US',
  srcExclude: ['website-plan.md', 'diagrams/**'],
  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: [/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/],
  sitemap: {
    hostname: siteHost,
    transformItems: items => items.filter(item => !item.url.includes('playground/callback'))
  },
  head: [
    ['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
    ['link', { rel: 'mask-icon', href: '/logo.svg', color: '#2563eb' }],
    ['meta', { name: 'theme-color', content: '#ffffff', media: '(prefers-color-scheme: light)' }],
    ['meta', { name: 'theme-color', content: '#111318', media: '(prefers-color-scheme: dark)' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'Quarkus Authorization Server' }],
    ...(isPreviewDeploy
      ? ([['meta', { name: 'robots', content: 'noindex, nofollow' }]] as const)
      : [])
  ],
  markdown: {
    config(md) {
      // Expand before parsing so prose, inline code and fenced examples share the same values.
      md.core.ruler.before('normalize', 'project-metadata', (state) => {
        state.src = replaceProjectPlaceholders(state.src, projectMetadata)
      })
    },
    theme: {
      light: 'github-light',
      dark: 'nord'
    }
  },
  vite: {
    define: {
      __DOCS_VERSION__: JSON.stringify(extensionVersion),
      __DOCS_COMMIT__: JSON.stringify(gitCommit),
      __DOCS_COMMIT_FULL__: JSON.stringify(gitCommitFull),
      __QUARKUS_VERSION__: JSON.stringify(quarkusVersion),
      __GITHUB_REPO__: JSON.stringify(githubRepo),
      __DIAGRAM_REVISION__: JSON.stringify(diagramRevision)
    }
  },
  transformPageData(pageData) {
    // Keep directory URLs consistent with navigation, including the locale homepages.
    const path = pageData.relativePath.replace(/(^|\/)index\.md$/, '$1').replace(/\.md$/, '')
    const canonical = new URL(path, `${siteHost}/`).href
    pageData.frontmatter.head ??= []
    pageData.frontmatter.head.push(['link', { rel: 'canonical', href: canonical }])
    pageData.frontmatter.head.push(['meta', { property: 'og:title', content: pageData.title }])
    pageData.frontmatter.head.push([
      'meta',
      { property: 'og:url', content: canonical }
    ])
  },
  themeConfig: {
    logo: { src: '/logo.svg', alt: 'Quarkus Authorization Server' },
    siteTitle: 'Authorization Server',
    externalLinkIcon: true,
    search: {
      provider: 'local',
      options: {
        locales: {
          zh: searchZh
        }
      }
    },
    socialLinks: [{ icon: 'github', link: githubRepo, ariaLabel: 'GitHub' }]
  },
  locales: {
    root: {
      label: 'English',
      lang: 'en-US',
      description:
        'A Quarkus extension that implements OAuth 2.0 and optional OpenID Connect authorization-server capabilities.',
      themeConfig: {
        nav: [
          { text: 'Docs', link: '/guide/', activeMatch: '/guide/' },
          { text: 'Reference', link: '/reference/', activeMatch: '/reference/' },
          { text: 'Playground', link: '/playground/', activeMatch: '/playground/' }
        ],
        sidebar: {
          '/guide/': [
            {
              text: 'Documentation',
              items: [
                { text: 'Introduction', link: '/guide/' },
                { text: 'Getting Started', link: '/guide/getting-started' },
                { text: 'Architecture', link: '/guide/architecture' },
                { text: 'Authorization Code + PKCE', link: '/guide/authorization-code' },
                { text: 'Client Credentials', link: '/guide/client-credentials' },
                { text: 'Other grants', link: '/guide/other-grants' },
                { text: 'Identity and access', link: '/guide/identity-and-access' },
                { text: 'Tokens and resource servers', link: '/guide/tokens-and-resources' },
                { text: 'Storage and signing keys', link: '/guide/storage-and-keys' }
              ]
            }
          ],
          '/reference/': [
            {
              text: 'Reference',
              items: [
                { text: 'Overview', link: '/reference/' },
                { text: 'Server configuration', link: '/reference/configuration' },
                { text: 'Registered clients', link: '/reference/clients' },
                { text: 'Signing keys', link: '/reference/signing' },
                { text: 'DPoP', link: '/reference/dpop' },
                { text: 'OAuth endpoints', link: '/reference/endpoints' },
                { text: 'OIDC and registration', link: '/reference/oidc-and-registration' },
                { text: 'CDI extension points', link: '/reference/extensions' },
                { text: 'Protocol support', link: '/reference/protocol-support' }
              ]
            }
          ],
          '/playground/': [
            {
              text: 'Playground',
              items: [
                { text: 'Live demo', link: '/playground/' },
                { text: 'PKCE generator', link: '/playground/pkce' },
                { text: 'JWT decoder', link: '/playground/jwt' },
                { text: 'Request builder', link: '/playground/requests' }
              ]
            }
          ]
        },
        outline: { label: 'On this page', level: [2, 3] },
        lastUpdated: { text: 'Last updated' },
        editLink: {
          pattern: `${githubRepo}/edit/main/docs/:path`,
          text: 'Edit this page on GitHub'
        },
        footer: {
          message: `Docs apply to ${extensionVersion} (${gitCommit}) · Quarkus ${quarkusVersion}`,
          copyright: 'Apache License 2.0'
        },
        notFound: {
          title: 'Page not found',
          quote: 'This URL is not part of the documentation site.',
          linkLabel: 'go to home',
          linkText: 'Take me home'
        }
      }
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      description: 'Quarkus 扩展：OAuth 2.0 与可选 OpenID Connect 授权服务器。',
      markdown: {
        container: {
          tipLabel: '提示',
          warningLabel: '注意',
          dangerLabel: '警告',
          infoLabel: '说明',
          detailsLabel: '详细信息'
        },
        codeCopyButtonTitle: '复制代码'
      },
      themeConfig: {
        nav: [
          { text: '文档', link: '/zh/guide/', activeMatch: '/zh/guide/' },
          { text: '参考', link: '/zh/reference/', activeMatch: '/zh/reference/' },
          { text: 'Playground', link: '/zh/playground/', activeMatch: '/zh/playground/' }
        ],
        sidebar: {
          '/zh/guide/': [
            {
              text: '文档',
              items: [
                { text: '介绍', link: '/zh/guide/' },
                { text: '快速开始', link: '/zh/guide/getting-started' },
                { text: '架构', link: '/zh/guide/architecture' },
                { text: 'Authorization Code + PKCE', link: '/zh/guide/authorization-code' },
                { text: 'Client Credentials', link: '/zh/guide/client-credentials' },
                { text: '其他授权流程', link: '/zh/guide/other-grants' },
                { text: '身份与权限', link: '/zh/guide/identity-and-access' },
                { text: 'Token 与资源服务器', link: '/zh/guide/tokens-and-resources' },
                { text: '存储与签名密钥', link: '/zh/guide/storage-and-keys' }
              ]
            }
          ],
          '/zh/reference/': [
            {
              text: '参考',
              items: [
                { text: '概览', link: '/zh/reference/' },
                { text: '服务端配置', link: '/zh/reference/configuration' },
                { text: '注册客户端', link: '/zh/reference/clients' },
                { text: '签名密钥', link: '/zh/reference/signing' },
                { text: 'DPoP', link: '/zh/reference/dpop' },
                { text: 'OAuth 端点', link: '/zh/reference/endpoints' },
                { text: 'OIDC 与注册', link: '/zh/reference/oidc-and-registration' },
                { text: 'CDI 扩展点', link: '/zh/reference/extensions' },
                { text: '协议能力与边界', link: '/zh/reference/protocol-support' }
              ]
            }
          ],
          '/zh/playground/': [
            {
              text: 'Playground',
              items: [
                { text: '在线演示', link: '/zh/playground/' },
                { text: 'PKCE 生成与核验', link: '/zh/playground/pkce' },
                { text: 'JWT 解码', link: '/zh/playground/jwt' },
                { text: '请求构造器', link: '/zh/playground/requests' }
              ]
            }
          ]
        },
        outline: { label: '本页目录', level: [2, 3] },
        lastUpdated: { text: '更新于' },
        editLink: {
          pattern: `${githubRepo}/edit/main/docs/:path`,
          text: '在 GitHub 上编辑'
        },
        docFooter: { prev: '上一页', next: '下一页' },
        darkModeSwitchLabel: '外观',
        lightModeSwitchTitle: '切换到浅色',
        darkModeSwitchTitle: '切换到深色',
        sidebarMenuLabel: '菜单',
        returnToTopLabel: '回到顶部',
        langMenuLabel: '切换语言',
        navMenuLabel: '网站导航',
        skipToContentLabel: '跳到正文',
        footer: {
          message: `文档适用于 ${extensionVersion}（${gitCommit}）· Quarkus ${quarkusVersion}`,
          copyright: 'Apache License 2.0'
        },
        notFound: {
          title: '没有这个页面',
          quote: '链接可能写错了，或者这一页还没有放进文档站。',
          linkLabel: '返回首页',
          linkText: '回到首页'
        }
      }
    }
  }
})
