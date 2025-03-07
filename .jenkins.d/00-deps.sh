#!/usr/bin/env bash
set -ex

if has OSX $NODE_LABELS; then
    FORMULAE=(boost openssl pkg-config)
    if [[ $JOB_NAME == *"Docs" ]]; then
        FORMULAE+=(doxygen graphviz)
    fi

    if [[ -n $GITHUB_ACTIONS ]]; then
        # GitHub Actions runners have a large number of pre-installed
        # Homebrew packages. Don't waste time upgrading all of them.
        brew list --versions "${FORMULAE[@]}" || brew update
        for FORMULA in "${FORMULAE[@]}"; do
            brew list --versions "$FORMULA" || brew install "$FORMULA"
        done
        # Ensure /usr/local/opt/openssl exists
        brew reinstall openssl
    else
        brew update
        brew upgrade
        brew install "${FORMULAE[@]}"
        brew cleanup
    fi

elif has Ubuntu $NODE_LABELS; then
    sudo apt-get -qq update
    sudo apt-get -qy install build-essential pkg-config python3-minimal \
                             libboost-all-dev libssl-dev libsqlite3-dev

    case $JOB_NAME in
        *code-coverage)
            sudo apt-get -qy install lcov python3-pip
            pip3 install --user --upgrade --upgrade-strategy=eager 'gcovr~=5.0'
            ;;
        *Docs)
            sudo apt-get -qy install doxygen graphviz
            ;;
    esac
fi
