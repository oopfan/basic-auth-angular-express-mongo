interface USER {
    [key: number]: {
        id: number,
        username: string,
        password: string
    }
}

export const USERS: USER = {
};
  
export function authenticate(username: string, password: string) {

    const user: any = Object.values(USERS).find(user => user.username === username);

    if (user && user.password == password) {
        return user;
    } else {
        return undefined;
    }

}

export function register(username: string, password: string, passwordConfirmation: string) {

    const user: any = Object.values(USERS).find(user => user.username === username);

    if (!user) {
        if (password == passwordConfirmation) {

            const nextid = Object.keys(USERS).reduce((prev, curr) => {
                return parseInt(curr) > parseInt(prev) ? curr : prev;
            }, '1');

            const id = parseInt(nextid) + 1;

            const newUser = {
                id,
                username,
                password
            };
    
            USERS[id] = newUser;
            return newUser;
        }
    }
    return undefined;
}

export function available(username: string) {

    const user: any = Object.values(USERS).find(user => user.username === username);
    return !user;
}
