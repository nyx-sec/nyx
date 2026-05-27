//! Runtime dependency hints for framework-bound dynamic harnesses.
//!
//! Framework adapters sometimes bind from marker text or framework
//! configuration while the entry source itself keeps the real import
//! commented out for host-portable corpus tests.  When such a binding is
//! used to drive a real harness, the build step still needs the matching
//! package manager manifest so top-level imports resolve under the verifier.

/// Package with a package-manager specific version requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionedPackage {
    pub name: &'static str,
    pub version: &'static str,
}

/// Maven dependency coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MavenPackage {
    pub group_id: &'static str,
    pub artifact_id: &'static str,
    pub version: &'static str,
}

/// Adapter runtime dependencies grouped by package manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameworkRuntimeDeps {
    pub python_packages: &'static [&'static str],
    pub node_packages: &'static [VersionedPackage],
    pub ruby_gems: &'static [&'static str],
    pub composer_packages: &'static [VersionedPackage],
    pub maven_packages: &'static [MavenPackage],
    pub go_modules: &'static [VersionedPackage],
    pub rust_crates: &'static [VersionedPackage],
}

impl FrameworkRuntimeDeps {
    pub const EMPTY: Self = Self {
        python_packages: &[],
        node_packages: &[],
        ruby_gems: &[],
        composer_packages: &[],
        maven_packages: &[],
        go_modules: &[],
        rust_crates: &[],
    };

    pub fn is_empty(&self) -> bool {
        self.python_packages.is_empty()
            && self.node_packages.is_empty()
            && self.ruby_gems.is_empty()
            && self.composer_packages.is_empty()
            && self.maven_packages.is_empty()
            && self.go_modules.is_empty()
            && self.rust_crates.is_empty()
    }
}

const PY_FLASK: &[&str] = &["Flask"];
const PY_FASTAPI: &[&str] = &["fastapi", "httpx"];
const PY_STARLETTE: &[&str] = &["starlette", "httpx"];
const PY_DJANGO: &[&str] = &["Django"];
const PY_CELERY: &[&str] = &["celery"];
const PY_GRAPHENE: &[&str] = &["graphene"];
const PY_CHANNELS: &[&str] = &["channels"];
const PY_SOCKETIO: &[&str] = &["python-socketio"];
const PY_ALEMBIC: &[&str] = &["alembic", "Flask-Migrate"];
const PY_KAFKA: &[&str] = &["kafka-python"];
const PY_SQS: &[&str] = &["boto3"];
const PY_PUBSUB: &[&str] = &["google-cloud-pubsub"];
const PY_RABBIT: &[&str] = &["pika"];

const NODE_EXPRESS: &[VersionedPackage] = &[VersionedPackage {
    name: "express",
    version: "^4.19.2",
}];
const NODE_KOA: &[VersionedPackage] = &[
    VersionedPackage {
        name: "koa",
        version: "^2.15.3",
    },
    VersionedPackage {
        name: "@koa/router",
        version: "^12.0.1",
    },
];
const NODE_FASTIFY: &[VersionedPackage] = &[VersionedPackage {
    name: "fastify",
    version: "^4.28.1",
}];
const NODE_CRON: &[VersionedPackage] = &[VersionedPackage {
    name: "node-cron",
    version: "^3.0.3",
}];
const NODE_APOLLO: &[VersionedPackage] = &[
    VersionedPackage {
        name: "@apollo/server",
        version: "^4.10.4",
    },
    VersionedPackage {
        name: "apollo-server",
        version: "^3.13.0",
    },
    VersionedPackage {
        name: "graphql",
        version: "^16.8.1",
    },
];
const NODE_RELAY: &[VersionedPackage] = &[
    VersionedPackage {
        name: "graphql-relay",
        version: "^0.10.0",
    },
    VersionedPackage {
        name: "graphql",
        version: "^16.8.1",
    },
];
const NODE_WS: &[VersionedPackage] = &[VersionedPackage {
    name: "ws",
    version: "^8.17.0",
}];
const NODE_SQS: &[VersionedPackage] = &[
    VersionedPackage {
        name: "@aws-sdk/client-sqs",
        version: "^3.583.0",
    },
    VersionedPackage {
        name: "sqs-consumer",
        version: "^11.5.0",
    },
];
const NODE_KNEX: &[VersionedPackage] = &[VersionedPackage {
    name: "knex",
    version: "^3.1.0",
}];
const NODE_PRISMA: &[VersionedPackage] = &[
    VersionedPackage {
        name: "@prisma/client",
        version: "^5.14.0",
    },
    VersionedPackage {
        name: "prisma",
        version: "^5.14.0",
    },
];
const NODE_SEQUELIZE: &[VersionedPackage] = &[
    VersionedPackage {
        name: "sequelize",
        version: "^6.37.3",
    },
    VersionedPackage {
        name: "sequelize-cli",
        version: "^6.6.2",
    },
    VersionedPackage {
        name: "sqlite3",
        version: "^5.1.7",
    },
];

const RUBY_RACK: &[&str] = &["rack"];
const RUBY_SINATRA: &[&str] = &["rack", "sinatra"];
const RUBY_HANAMI: &[&str] = &["rack", "hanami-controller"];
const RUBY_RAILS: &[&str] = &["rails"];
const RUBY_SIDEKIQ: &[&str] = &["sidekiq"];

const PHP_LARAVEL: &[VersionedPackage] = &[VersionedPackage {
    name: "laravel/framework",
    version: "^10.0",
}];
const PHP_SYMFONY: &[VersionedPackage] = &[
    VersionedPackage {
        name: "symfony/http-foundation",
        version: "^6.4",
    },
    VersionedPackage {
        name: "symfony/http-kernel",
        version: "^6.4",
    },
];
const PHP_CODEIGNITER: &[VersionedPackage] = &[VersionedPackage {
    name: "codeigniter4/framework",
    version: "^4.4",
}];

const JAVA_SPRING: &[MavenPackage] = &[MavenPackage {
    group_id: "org.springframework",
    artifact_id: "spring-webmvc",
    version: "6.1.8",
}];
const JAVA_SERVLET: &[MavenPackage] = &[
    MavenPackage {
        group_id: "jakarta.servlet",
        artifact_id: "jakarta.servlet-api",
        version: "6.0.0",
    },
    MavenPackage {
        group_id: "javax.servlet",
        artifact_id: "javax.servlet-api",
        version: "4.0.1",
    },
];
const JAVA_QUARTZ: &[MavenPackage] = &[MavenPackage {
    group_id: "org.quartz-scheduler",
    artifact_id: "quartz",
    version: "2.3.2",
}];
const JAVA_FLYWAY: &[MavenPackage] = &[MavenPackage {
    group_id: "org.flywaydb",
    artifact_id: "flyway-core",
    version: "10.13.0",
}];
const JAVA_LIQUIBASE: &[MavenPackage] = &[MavenPackage {
    group_id: "org.liquibase",
    artifact_id: "liquibase-core",
    version: "4.28.0",
}];
const JAVA_KAFKA: &[MavenPackage] = &[MavenPackage {
    group_id: "org.apache.kafka",
    artifact_id: "kafka-clients",
    version: "3.7.0",
}];
const JAVA_SQS: &[MavenPackage] = &[MavenPackage {
    group_id: "software.amazon.awssdk",
    artifact_id: "sqs",
    version: "2.25.60",
}];
const JAVA_RABBIT: &[MavenPackage] = &[MavenPackage {
    group_id: "com.rabbitmq",
    artifact_id: "amqp-client",
    version: "5.21.0",
}];
const JAVA_QUARKUS: &[MavenPackage] = &[MavenPackage {
    group_id: "io.quarkus",
    artifact_id: "quarkus-resteasy-reactive",
    version: "3.10.2",
}];
const JAVA_MICRONAUT: &[MavenPackage] = &[MavenPackage {
    group_id: "io.micronaut",
    artifact_id: "micronaut-http-server-netty",
    version: "4.4.4",
}];

const GO_GIN: &[VersionedPackage] = &[VersionedPackage {
    name: "github.com/gin-gonic/gin",
    version: "v1.10.0",
}];
const GO_ECHO: &[VersionedPackage] = &[VersionedPackage {
    name: "github.com/labstack/echo/v4",
    version: "v4.12.0",
}];
const GO_FIBER: &[VersionedPackage] = &[VersionedPackage {
    name: "github.com/gofiber/fiber/v2",
    version: "v2.52.5",
}];
const GO_CHI: &[VersionedPackage] = &[VersionedPackage {
    name: "github.com/go-chi/chi/v5",
    version: "v5.0.12",
}];
const GO_GQLGEN: &[VersionedPackage] = &[VersionedPackage {
    name: "github.com/99designs/gqlgen",
    version: "v0.17.49",
}];
const GO_MIGRATE: &[VersionedPackage] = &[VersionedPackage {
    name: "github.com/golang-migrate/migrate/v4",
    version: "v4.17.1",
}];
const GO_PUBSUB: &[VersionedPackage] = &[VersionedPackage {
    name: "cloud.google.com/go/pubsub",
    version: "v1.39.0",
}];
const GO_NATS: &[VersionedPackage] = &[VersionedPackage {
    name: "github.com/nats-io/nats.go",
    version: "v1.34.1",
}];

const RUST_AXUM: &[VersionedPackage] = &[
    VersionedPackage {
        name: "axum",
        version: "0.7",
    },
    VersionedPackage {
        name: "tokio",
        version: "1",
    },
];
const RUST_ACTIX: &[VersionedPackage] = &[VersionedPackage {
    name: "actix-web",
    version: "4",
}];
const RUST_ROCKET: &[VersionedPackage] = &[VersionedPackage {
    name: "rocket",
    version: "0.5",
}];
const RUST_WARP: &[VersionedPackage] = &[
    VersionedPackage {
        name: "warp",
        version: "0.3",
    },
    VersionedPackage {
        name: "tokio",
        version: "1",
    },
];
const RUST_JUNIPER: &[VersionedPackage] = &[VersionedPackage {
    name: "juniper",
    version: "0.16",
}];
const RUST_REFINERY: &[VersionedPackage] = &[VersionedPackage {
    name: "refinery",
    version: "0.8",
}];
const RUST_SQLX: &[VersionedPackage] = &[VersionedPackage {
    name: "sqlx",
    version: "0.7",
}];

/// Dependencies known for a framework adapter id.
pub fn deps_for_adapter(adapter: &str) -> FrameworkRuntimeDeps {
    match adapter {
        "python-flask" => FrameworkRuntimeDeps {
            python_packages: PY_FLASK,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "python-fastapi" => FrameworkRuntimeDeps {
            python_packages: PY_FASTAPI,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "python-starlette" => FrameworkRuntimeDeps {
            python_packages: PY_STARLETTE,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "python-django" | "middleware-django" | "migration-django" => FrameworkRuntimeDeps {
            python_packages: PY_DJANGO,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "scheduled-celery" => FrameworkRuntimeDeps {
            python_packages: PY_CELERY,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "graphql-graphene" => FrameworkRuntimeDeps {
            python_packages: PY_GRAPHENE,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "websocket-channels" => FrameworkRuntimeDeps {
            python_packages: PY_CHANNELS,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "websocket-socketio" => FrameworkRuntimeDeps {
            python_packages: PY_SOCKETIO,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "migration-flask" => FrameworkRuntimeDeps {
            python_packages: PY_ALEMBIC,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "kafka-python" => FrameworkRuntimeDeps {
            python_packages: PY_KAFKA,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "sqs-python" => FrameworkRuntimeDeps {
            python_packages: PY_SQS,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "pubsub-python" => FrameworkRuntimeDeps {
            python_packages: PY_PUBSUB,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "rabbit-python" => FrameworkRuntimeDeps {
            python_packages: PY_RABBIT,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "js-express" | "middleware-express" => FrameworkRuntimeDeps {
            node_packages: NODE_EXPRESS,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "js-koa" => FrameworkRuntimeDeps {
            node_packages: NODE_KOA,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "js-fastify" => FrameworkRuntimeDeps {
            node_packages: NODE_FASTIFY,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "scheduled-cron" => FrameworkRuntimeDeps {
            node_packages: NODE_CRON,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "graphql-apollo" => FrameworkRuntimeDeps {
            node_packages: NODE_APOLLO,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "graphql-relay" => FrameworkRuntimeDeps {
            node_packages: NODE_RELAY,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "websocket-ws" => FrameworkRuntimeDeps {
            node_packages: NODE_WS,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "sqs-node" => FrameworkRuntimeDeps {
            node_packages: NODE_SQS,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "migration-knex" => FrameworkRuntimeDeps {
            node_packages: NODE_KNEX,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "migration-prisma" => FrameworkRuntimeDeps {
            node_packages: NODE_PRISMA,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "migration-sequelize" => FrameworkRuntimeDeps {
            node_packages: NODE_SEQUELIZE,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "ruby-sinatra" => FrameworkRuntimeDeps {
            ruby_gems: RUBY_SINATRA,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "ruby-hanami" => FrameworkRuntimeDeps {
            ruby_gems: RUBY_HANAMI,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "ruby-rails" | "middleware-rails" | "migration-rails" | "websocket-actioncable" => {
            FrameworkRuntimeDeps {
                ruby_gems: RUBY_RAILS,
                ..FrameworkRuntimeDeps::EMPTY
            }
        }
        "scheduled-sidekiq" => FrameworkRuntimeDeps {
            ruby_gems: RUBY_SIDEKIQ,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "middleware-rack" => FrameworkRuntimeDeps {
            ruby_gems: RUBY_RACK,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "php-laravel" | "middleware-laravel" | "migration-laravel" => FrameworkRuntimeDeps {
            composer_packages: PHP_LARAVEL,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "php-symfony" => FrameworkRuntimeDeps {
            composer_packages: PHP_SYMFONY,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "php-codeigniter" => FrameworkRuntimeDeps {
            composer_packages: PHP_CODEIGNITER,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "java-spring" | "middleware-spring" => FrameworkRuntimeDeps {
            maven_packages: JAVA_SPRING,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "java-servlet" => FrameworkRuntimeDeps {
            maven_packages: JAVA_SERVLET,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "java-quarkus" => FrameworkRuntimeDeps {
            maven_packages: JAVA_QUARKUS,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "java-micronaut" => FrameworkRuntimeDeps {
            maven_packages: JAVA_MICRONAUT,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "scheduled-quartz" => FrameworkRuntimeDeps {
            maven_packages: JAVA_QUARTZ,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "migration-flyway" => FrameworkRuntimeDeps {
            maven_packages: JAVA_FLYWAY,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "migration-liquibase" => FrameworkRuntimeDeps {
            maven_packages: JAVA_LIQUIBASE,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "kafka-java" => FrameworkRuntimeDeps {
            maven_packages: JAVA_KAFKA,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "sqs-java" => FrameworkRuntimeDeps {
            maven_packages: JAVA_SQS,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "rabbit-java" => FrameworkRuntimeDeps {
            maven_packages: JAVA_RABBIT,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "go-gin" => FrameworkRuntimeDeps {
            go_modules: GO_GIN,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "go-echo" => FrameworkRuntimeDeps {
            go_modules: GO_ECHO,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "go-fiber" => FrameworkRuntimeDeps {
            go_modules: GO_FIBER,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "go-chi" => FrameworkRuntimeDeps {
            go_modules: GO_CHI,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "graphql-gqlgen" => FrameworkRuntimeDeps {
            go_modules: GO_GQLGEN,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "migration-go-migrate" => FrameworkRuntimeDeps {
            go_modules: GO_MIGRATE,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "pubsub-go" => FrameworkRuntimeDeps {
            go_modules: GO_PUBSUB,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "nats-go" => FrameworkRuntimeDeps {
            go_modules: GO_NATS,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "rust-axum" => FrameworkRuntimeDeps {
            rust_crates: RUST_AXUM,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "rust-actix" => FrameworkRuntimeDeps {
            rust_crates: RUST_ACTIX,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "rust-rocket" => FrameworkRuntimeDeps {
            rust_crates: RUST_ROCKET,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "rust-warp" => FrameworkRuntimeDeps {
            rust_crates: RUST_WARP,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "graphql-juniper" => FrameworkRuntimeDeps {
            rust_crates: RUST_JUNIPER,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "migration-refinery" => FrameworkRuntimeDeps {
            rust_crates: RUST_REFINERY,
            ..FrameworkRuntimeDeps::EMPTY
        },
        "migration-sqlx" => FrameworkRuntimeDeps {
            rust_crates: RUST_SQLX,
            ..FrameworkRuntimeDeps::EMPTY
        },
        _ => FrameworkRuntimeDeps::EMPTY,
    }
}
