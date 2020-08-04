import * as dotenv from 'dotenv';
dotenv.config();

import * as mongoose from 'mongoose';
import { app } from './index';

mongoose.connect(process.env.MONGO_CONNECT, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
});

const port = process.env.PORT;

app.listen(port, () => {
    console.log('Express server listening on port ' + port);
});
