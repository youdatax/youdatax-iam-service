/*
 * \extensions\common\iam\decentralized-claims\decentralized-claims-sts\lib\decentralized-claims-sts-remote-lib
 */

plugins {
    `java-library`
    `maven-publish`
}

dependencies {
    api(project(":spi:common:decentralized-claims-spi"))
    api(project(":spi:common:oauth2-spi"))
    api(project(":spi:common:jwt-spi"))

    testImplementation(project(":core:common:junit"))
}

